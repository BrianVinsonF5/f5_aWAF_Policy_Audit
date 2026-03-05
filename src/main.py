"""
CLI entry point for the F5 BIG-IP ASM/AWAF Security Policy Auditor.

Usage:
    python -m src.main --host 192.168.1.245 --username admin --baseline ./baseline/corp.xml
"""
import argparse
import getpass
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

import yaml

from .utils import setup_logging, get_logger, ensure_dir, iso_timestamp
from .bigip_client import BigIPClient, AuthenticationError
from .policy_exporter import PolicyExporter, ExportError
from .policy_parser import parse_policy, get_policy_metadata
from .policy_comparator import compare_policies
from .report_generator import generate_html, generate_markdown, generate_summary_reports

try:
    from tqdm import tqdm as _tqdm
    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

import urllib3


_PASS_THRESHOLD = 90.0


# ── Config loading ─────────────────────────────────────────────────────────────

def _load_config(path: Optional[str]) -> dict:
    if path and Path(path).exists():
        with open(path, encoding='utf-8') as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _resolve(cli_val, env_var: str, config_val, default=None):
    """Precedence: CLI → env → config → default."""
    if cli_val is not None:
        return cli_val
    env_val = os.environ.get(env_var)
    if env_val is not None:
        return env_val
    if config_val is not None:
        return config_val
    return default


# ── Argument parsing ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="f5-awaf-auditor",
        description=(
            "F5 BIG-IP ASM/AWAF Security Policy Auditor — "
            "Read-only compliance audit of WAF policies against a baseline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--config", metavar="FILE",
                   help="Path to YAML config file (default: config.yaml)")
    p.add_argument("--host", metavar="HOST",
                   help="BIG-IP management IP or FQDN [env: BIGIP_HOST]")
    p.add_argument("--username", metavar="USER",
                   help="Admin username [env: BIGIP_USER]")
    # NOTE: --password is intentionally absent. Supply credentials via the
    # BIGIP_PASS environment variable or the interactive prompt to avoid
    # exposing the password in the process table (ps aux).
    p.add_argument("--baseline", metavar="FILE",
                   help="Path to baseline XML policy file")
    p.add_argument("--output-dir", metavar="DIR", default=None,
                   help="Output directory for exports and reports (default: ./output)")
    p.add_argument("--format", dest="report_format",
                   choices=["html", "markdown", "both"], default=None,
                   help="Report format (default: both)")
    p.add_argument("--partitions", metavar="P1,P2",
                   help="Comma-separated partition names to audit (default: all)")
    p.add_argument("--export-format", dest="export_format",
                   choices=["xml", "json"], default=None,
                   help="Policy export format (default: xml)")
    p.add_argument("--verify-ssl", dest="verify_ssl", action="store_true",
                   default=None, help="Enable TLS certificate verification (default)")
    p.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false",
                   help="Disable TLS certificate verification (for self-signed certs)")
    p.add_argument("--login-provider", dest="login_provider", metavar="PROVIDER",
                   default=None,
                   help="BIG-IP login provider name [env: BIGIP_LOGIN_PROVIDER] (default: tmos)")
    p.add_argument("--concurrent-exports", dest="concurrent_exports",
                   type=int, default=None, metavar="N",
                   help="Max parallel export tasks, 1–20 (default: 3)")
    p.add_argument("-v", "--verbose", action="store_true", default=False,
                   help="Enable debug logging")
    return p


# ── Validation helpers ─────────────────────────────────────────────────────────

def _validate_xml(path: str) -> None:
    """Abort with a clear message if the file is not valid XML."""
    try:
        ET.parse(path)
    except ET.ParseError as exc:
        sys.exit(f"ERROR: Baseline policy '{path}' is not valid XML: {exc}")


# ── Main workflow ──────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Load config file
    config_path = args.config or "config.yaml"
    raw_cfg = _load_config(config_path)
    bigip_cfg = raw_cfg.get("bigip", {})
    audit_cfg = raw_cfg.get("audit", {})

    # Resolve parameters
    host     = _resolve(args.host,     "BIGIP_HOST", bigip_cfg.get("host"))
    username = _resolve(args.username, "BIGIP_USER", bigip_cfg.get("username"))
    # Password must come from the environment or an interactive prompt.
    # Accepting it from the config file would encourage storing plaintext
    # credentials on disk.  BIGIP_PASS env var is still permitted (e.g. CI).
    if bigip_cfg.get("password"):
        print(
            "ERROR: 'password' in the config file is not supported. "
            "Use the BIGIP_PASS environment variable or the interactive prompt.",
            file=sys.stderr,
        )
        return 1
    password = os.environ.get("BIGIP_PASS")
    login_provider = _resolve(
        args.login_provider, "BIGIP_LOGIN_PROVIDER",
        bigip_cfg.get("login_provider"), "tmos"
    )
    baseline = _resolve(args.baseline, "BASELINE_POLICY", audit_cfg.get("baseline_policy"))
    output_dir = _resolve(args.output_dir, "OUTPUT_DIR",
                          audit_cfg.get("output_dir"), "./output")
    report_format = _resolve(args.report_format, "REPORT_FORMAT",
                             audit_cfg.get("report_format"), "both")
    export_format = _resolve(args.export_format, "EXPORT_FORMAT",
                             audit_cfg.get("export_format"), "xml")
    # SSL verification defaults to True; coerce string env-var values correctly
    # so that VERIFY_SSL=false doesn't silently evaluate to True.
    _raw_ssl = _resolve(args.verify_ssl, "VERIFY_SSL", bigip_cfg.get("verify_ssl"), True)
    if isinstance(_raw_ssl, str):
        verify_ssl = _raw_ssl.lower() in ("1", "true", "yes")
    else:
        verify_ssl = bool(_raw_ssl)
    concurrent = _resolve(args.concurrent_exports, "CONCURRENT_EXPORTS",
                          audit_cfg.get("concurrent_exports"), 3)
    partitions_str = _resolve(args.partitions, "PARTITIONS",
                              None, "")
    if partitions_str:
        partitions = [p.strip() for p in partitions_str.split(',') if p.strip()]
    else:
        partitions = audit_cfg.get("partitions") or []

    verbose = args.verbose

    # Setup logging first
    ensure_dir(output_dir)
    log = setup_logging(verbose, output_dir)
    logger = get_logger("main")

    # Validate required arguments
    missing = []
    if not host:
        missing.append("--host / BIGIP_HOST")
    if not username:
        missing.append("--username / BIGIP_USER")
    if not baseline:
        missing.append("--baseline")
    if missing:
        parser.print_usage()
        print(f"\nERROR: Missing required arguments: {', '.join(missing)}")
        return 1

    # Validate concurrent_exports range
    try:
        concurrent = int(concurrent)
    except (TypeError, ValueError):
        print("ERROR: --concurrent-exports must be an integer between 1 and 20.")
        return 1
    if not 1 <= concurrent <= 20:
        print(f"ERROR: --concurrent-exports must be between 1 and 20 (got {concurrent}).")
        return 1

    # Password prompt if needed
    if not password:
        try:
            password = getpass.getpass(f"Password for {username}@{host}: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 1

    # Validate baseline
    baseline = str(Path(baseline).resolve())
    if not Path(baseline).exists():
        logger.error("Baseline policy file not found: %s", baseline)
        return 1
    logger.info("Validating baseline XML …")
    _validate_xml(baseline)

    # SSL warning — loud enough to be noticed when the user opts out of verification
    if not verify_ssl:
        logger.warning(
            "SSL verification is DISABLED (--no-verify-ssl). "
            "Only use this for self-signed certificates in trusted environments. "
            "Remove --no-verify-ssl and supply a valid CA bundle in production."
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Determine report formats
    formats: List[str] = []
    if report_format == "both":
        formats = ["html", "markdown"]
    else:
        formats = [report_format]

    # ── Connect & authenticate ─────────────────────────────────────────────────
    logger.info("Connecting to BIG-IP at %s …", host)
    client = BigIPClient(
        host=host,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        verbose=verbose,
        login_provider=login_provider,
    )
    try:
        client.authenticate()
    except AuthenticationError as exc:
        logger.error("Authentication failed: %s", exc)
        return 1
    except Exception as exc:
        logger.error("Cannot connect to BIG-IP: %s", exc)
        return 1
    logger.info("Authenticated successfully.")

    # ── Discover partitions & policies ────────────────────────────────────────
    exporter = PolicyExporter(
        client=client,
        output_dir=output_dir,
        export_format=export_format,
        concurrent_exports=concurrent,
        partitions=partitions if partitions else None,
    )
    try:
        all_partitions = exporter.discover_partitions()
    except Exception as exc:
        logger.error("Partition discovery failed: %s", exc)
        client.close()
        return 1

    try:
        policies = exporter.discover_policies(all_partitions)
    except ExportError as exc:
        logger.error("Policy discovery failed: %s", exc)
        client.close()
        return 1

    if not policies:
        logger.warning("No ASM/AWAF policies found. Exiting.")
        client.close()
        return 0

    exporter.print_discovery_table(policies)

    # ── Enrich with virtual server bindings ───────────────────────────────────
    exporter.enrich_with_virtual_servers(policies)

    # ── Export policies ───────────────────────────────────────────────────────
    successes, failures = exporter.export_all(policies)
    if failures:
        logger.warning(
            "%d policy export(s) failed (see log for details):", len(failures)
        )
        for policy, err in failures:
            logger.warning("  %s: %s", policy["fullPath"], err)

    if not successes:
        logger.error("All exports failed. No policies to audit.")
        client.close()
        return 1

    client.close()

    # ── Parse baseline ────────────────────────────────────────────────────────
    logger.info("Parsing baseline policy: %s", baseline)
    try:
        baseline_data = parse_policy(baseline)
    except Exception as exc:
        logger.error("Failed to parse baseline policy: %s", exc)
        return 1
    baseline_name = Path(baseline).name

    # ── Compare and report ────────────────────────────────────────────────────
    all_results = []
    total = len(successes)
    iterable = (
        tqdm(successes, desc="Auditing policies", unit="policy")
        if _HAS_TQDM
        else successes
    )

    for idx, policy in enumerate(iterable, 1):
        local_path = policy.get("local_path")
        if not local_path or not Path(local_path).exists():
            logger.error("Exported file missing for %s", policy["fullPath"])
            continue

        logger.info("Auditing policy %d/%d: %s", idx, total, policy["fullPath"])
        try:
            target_data = parse_policy(local_path)
            meta = get_policy_metadata(local_path)
            # Supplement metadata from discovery if parser couldn't get it
            if not meta.get("name"):
                meta["name"] = policy["name"]
            if not meta.get("fullPath"):
                meta["fullPath"] = policy["fullPath"]
        except Exception as exc:
            logger.error("Failed to parse exported policy %s: %s",
                         policy["fullPath"], exc)
            continue

        cmp_result = compare_policies(
            baseline=baseline_data,
            target=target_data,
            policy_meta=meta,
            baseline_name=baseline_name,
            virtual_servers=policy.get("virtual_servers", []),
        )
        all_results.append(cmp_result)

        if "markdown" in formats:
            generate_markdown(cmp_result, output_dir)
        if "html" in formats:
            generate_html(cmp_result, output_dir)

    # ── Summary report ────────────────────────────────────────────────────────
    if all_results:
        generate_summary_reports(all_results, output_dir, formats)

    # ── Final stdout summary ──────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print(f"{'POLICY AUDIT SUMMARY':^72}")
    print("=" * 72)
    header = f"{'Policy':<40} {'Score':>7}  {'Status':<6}  {'Critical':>8}  {'Warn':>5}"
    print(header)
    print("-" * 72)

    any_fail = False
    for r in sorted(all_results, key=lambda x: x.score):
        status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
        if status == "FAIL":
            any_fail = True
        totals = r.summary.get("totals", {})
        crit = totals.get("critical", 0)
        warn = totals.get("warning", 0)
        # Truncate long names
        name = r.policy_path
        if len(name) > 38:
            name = "…" + name[-37:]
        print(f"{name:<40} {r.score:>6.1f}%  {status:<6}  {crit:>8}  {warn:>5}")

    print("=" * 72)

    if failures:
        print(f"\nWARNING: {len(failures)} policy export(s) failed and were not audited.")

    reports_dir = Path(output_dir) / "reports"
    print(f"\nReports written to: {reports_dir}")
    print(f"Log file:           {Path(output_dir)}/audit_*.log")

    exit_code = 1 if any_fail else 0
    if any_fail:
        print(f"\nRESULT: FAIL — one or more policies scored below {_PASS_THRESHOLD:.0f}%")
    else:
        print(f"\nRESULT: PASS — all policies scored >= {_PASS_THRESHOLD:.0f}%")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
