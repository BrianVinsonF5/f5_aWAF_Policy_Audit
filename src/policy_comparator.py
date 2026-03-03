"""
Policy comparison (diff) engine.

Compares a parsed target policy against a parsed baseline policy and
produces a ComparisonResult with severity-annotated DiffItem entries and
a compliance score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .utils import get_logger, iso_timestamp

_log = get_logger("policy_comparator")

SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING  = "warning"
SEVERITY_INFO     = "info"

# Scoring deductions per severity
_DEDUCT = {
    SEVERITY_CRITICAL: 5.0,
    SEVERITY_WARNING:  2.0,
    SEVERITY_INFO:     0.5,
}


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class DiffItem:
    section:        str
    element_name:   str
    attribute:      str
    baseline_value: Any
    target_value:   Any
    severity:       str
    description:    str


@dataclass
class ComparisonResult:
    policy_name:     str
    policy_path:     str
    partition:       str
    enforcement_mode: str
    baseline_name:   str
    timestamp:       str
    summary:         Dict   = field(default_factory=dict)
    diffs:           List[DiffItem] = field(default_factory=list)
    missing_in_target: List = field(default_factory=list)
    extra_in_target:   List = field(default_factory=list)
    score:           float = 100.0


# ── Main entry point ───────────────────────────────────────────────────────────

def compare_policies(
    baseline: Dict,
    target: Dict,
    policy_meta: Optional[Dict] = None,
    baseline_name: str = "baseline",
) -> ComparisonResult:
    """
    Compare a target policy dict against a baseline policy dict.

    Both dicts must come from policy_parser.parse_policy().
    policy_meta is the result of policy_parser.get_policy_metadata() for target.
    """
    meta = policy_meta or {}
    result = ComparisonResult(
        policy_name=meta.get("name", "unknown"),
        policy_path=meta.get("fullPath", "unknown"),
        partition=meta.get("fullPath", "/Common/unknown").strip('/').split('/')[0],
        enforcement_mode=target.get("general", {}).get("enforcementMode", "transparent"),
        baseline_name=baseline_name,
        timestamp=iso_timestamp(),
    )

    # Run each section comparator
    _cmp_general(baseline, target, result)
    _cmp_blocking_settings(baseline, target, result)
    _cmp_attack_signatures(baseline, target, result)
    _cmp_signature_sets(baseline, target, result)
    _cmp_named_list(
        baseline.get("urls", []),
        target.get("urls", []),
        section="urls",
        key="name",
        attrs=["isAllowed", "attackSignaturesCheck", "metacharsOnUrlCheck"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("filetypes", []),
        target.get("filetypes", []),
        section="filetypes",
        key="name",
        attrs=["allowed", "responseCheck"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("parameters", []),
        target.get("parameters", []),
        section="parameters",
        key="name",
        attrs=["allowEmptyValue", "checkAttackSignatures", "checkMetachars", "sensitiveParameter"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("headers", []),
        target.get("headers", []),
        section="headers",
        key="name",
        attrs=["mandatory", "checkSignatures"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("cookies", []),
        target.get("cookies", []),
        section="cookies",
        key="name",
        attrs=["enforcementType", "insertSameSiteAttribute", "decodeValueAsBase64"],
        result=result,
    )
    _cmp_named_list(
        baseline.get("methods", []),
        target.get("methods", []),
        section="methods",
        key="name",
        attrs=["actAsMethod"],
        result=result,
    )
    _cmp_data_guard(baseline, target, result)
    _cmp_ip_intelligence(baseline, target, result)
    _cmp_bot_defense(baseline, target, result)
    _cmp_whitelist_ips(baseline, target, result)

    # Build summary and calculate score
    _build_summary(result)
    result.score = _calculate_score(result.diffs)

    return result


# ── Section comparators ────────────────────────────────────────────────────────

def _add(result: ComparisonResult, item: DiffItem) -> None:
    result.diffs.append(item)


def _cmp_general(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    b_gen = baseline.get("general", {})
    t_gen = target.get("general", {})

    # enforcementMode: baseline=blocking, target=transparent → CRITICAL
    b_mode = b_gen.get("enforcementMode", "transparent")
    t_mode = t_gen.get("enforcementMode", "transparent")
    if b_mode != t_mode:
        sev = SEVERITY_CRITICAL if (b_mode == "blocking" and t_mode != "blocking") else SEVERITY_WARNING
        _add(result, DiffItem(
            section="general",
            element_name="enforcementMode",
            attribute="enforcementMode",
            baseline_value=b_mode,
            target_value=t_mode,
            severity=sev,
            description=(
                "Policy enforcement mode differs from baseline. "
                f"Baseline: {b_mode}, Target: {t_mode}."
                + (" Policy is NOT blocking threats." if sev == SEVERITY_CRITICAL else "")
            ),
        ))

    # Simple boolean/string settings
    _simple_attrs = [
        ("signatureStaging",      SEVERITY_WARNING,  "Signature staging setting differs."),
        ("responseLogging",       SEVERITY_INFO,     "Response logging setting differs."),
        ("maskCreditCardNumbers", SEVERITY_WARNING,  "Credit card masking setting differs."),
        ("trustXff",              SEVERITY_WARNING,  "Trust X-Forwarded-For setting differs."),
    ]
    for attr, sev, desc in _simple_attrs:
        b_val = b_gen.get(attr)
        t_val = t_gen.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="general",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))


def _cmp_blocking_settings(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_bs = baseline.get("blocking-settings", {})
    t_bs = target.get("blocking-settings", {})

    for sub_section in ("violations", "evasions", "http-protocols"):
        b_items = {item["name"]: item for item in b_bs.get(sub_section, [])}
        t_items = {item["name"]: item for item in t_bs.get(sub_section, [])}
        section_key = f"blocking-settings.{sub_section}"

        for name, b_item in b_items.items():
            if name not in t_items:
                result.missing_in_target.append(
                    {"section": section_key, "name": name}
                )
                _add(result, DiffItem(
                    section=section_key,
                    element_name=name,
                    attribute="(all)",
                    baseline_value="present",
                    target_value="missing",
                    severity=SEVERITY_WARNING,
                    description=f"'{name}' is defined in baseline but missing from target policy.",
                ))
                continue

            t_item = t_items[name]
            for attr in ("alarm", "block", "learn"):
                b_val = b_item.get(attr)
                t_val = t_item.get(attr)
                if b_val != t_val:
                    # block=True in baseline but False in target → CRITICAL
                    sev = (
                        SEVERITY_CRITICAL
                        if attr == "block" and b_val is True and t_val is False
                        else SEVERITY_WARNING
                    )
                    desc = (
                        f"Protection disabled: '{name}' has block=True in baseline "
                        "but block=False in target. Attacks will NOT be blocked."
                        if sev == SEVERITY_CRITICAL
                        else f"'{name}' {attr} setting differs from baseline."
                    )
                    _add(result, DiffItem(
                        section=section_key,
                        element_name=name,
                        attribute=attr,
                        baseline_value=b_val,
                        target_value=t_val,
                        severity=sev,
                        description=desc,
                    ))

        for name in t_items:
            if name not in b_items:
                result.extra_in_target.append(
                    {"section": section_key, "name": name}
                )


def _cmp_attack_signatures(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_sigs = {s["signatureId"]: s for s in baseline.get("attack-signatures", [])}
    t_sigs = {s["signatureId"]: s for s in target.get("attack-signatures", [])}

    if not b_sigs:
        return

    matched = missing = disabled = staging = 0

    for sig_id, b_sig in b_sigs.items():
        if sig_id not in t_sigs:
            missing += 1
            result.missing_in_target.append(
                {"section": "attack-signatures", "signatureId": sig_id}
            )
            continue

        t_sig = t_sigs[sig_id]
        matched += 1

        if b_sig.get("enabled") and not t_sig.get("enabled"):
            disabled += 1
            _add(result, DiffItem(
                section="attack-signatures",
                element_name=str(sig_id),
                attribute="enabled",
                baseline_value=True,
                target_value=False,
                severity=SEVERITY_CRITICAL,
                description=f"Signature {sig_id} is enabled in baseline but disabled in target.",
            ))

        if not b_sig.get("performStaging") and t_sig.get("performStaging"):
            staging += 1
            _add(result, DiffItem(
                section="attack-signatures",
                element_name=str(sig_id),
                attribute="performStaging",
                baseline_value=False,
                target_value=True,
                severity=SEVERITY_WARNING,
                description=(
                    f"Signature {sig_id} is active in baseline but still in staging "
                    "in target (will not enforce)."
                ),
            ))

    for sig_id in t_sigs:
        if sig_id not in b_sigs:
            result.extra_in_target.append(
                {"section": "attack-signatures", "signatureId": sig_id}
            )

    _log.debug(
        "Signature comparison: %d matched, %d missing, %d disabled, %d staging.",
        matched, missing, disabled, staging,
    )


def _cmp_signature_sets(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_sets = {s["name"]: s for s in baseline.get("signature-sets", [])}
    t_sets = {s["name"]: s for s in target.get("signature-sets", [])}

    for name, b_set in b_sets.items():
        if name not in t_sets:
            result.missing_in_target.append({"section": "signature-sets", "name": name})
            _add(result, DiffItem(
                section="signature-sets",
                element_name=name,
                attribute="(all)",
                baseline_value="present",
                target_value="missing",
                severity=SEVERITY_WARNING,
                description=f"Signature set '{name}' is in baseline but missing from target.",
            ))
            continue

        t_set = t_sets[name]
        for attr in ("alarm", "block", "learn"):
            b_val = b_set.get(attr)
            t_val = t_set.get(attr)
            if b_val != t_val:
                sev = (
                    SEVERITY_CRITICAL
                    if attr == "block" and b_val is True and t_val is False
                    else SEVERITY_WARNING
                )
                _add(result, DiffItem(
                    section="signature-sets",
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=f"Signature set '{name}' {attr} differs from baseline.",
                ))

    for name in t_sets:
        if name not in b_sets:
            result.extra_in_target.append({"section": "signature-sets", "name": name})


def _cmp_named_list(
    b_list: List[Dict],
    t_list: List[Dict],
    section: str,
    key: str,
    attrs: List[str],
    result: ComparisonResult,
    missing_severity: str = SEVERITY_WARNING,
    attr_severity: str = SEVERITY_WARNING,
) -> None:
    b_map = {item[key]: item for item in b_list}
    t_map = {item[key]: item for item in t_list}

    for name, b_item in b_map.items():
        if name not in t_map:
            result.missing_in_target.append({"section": section, key: name})
            _add(result, DiffItem(
                section=section,
                element_name=name,
                attribute="(all)",
                baseline_value="present",
                target_value="missing",
                severity=missing_severity,
                description=f"{section} '{name}' defined in baseline is missing from target.",
            ))
            continue

        t_item = t_map[name]
        for attr in attrs:
            b_val = b_item.get(attr)
            t_val = t_item.get(attr)
            if b_val is not None and b_val != t_val:
                _add(result, DiffItem(
                    section=section,
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=attr_severity,
                    description=f"{section} '{name}' attribute '{attr}' differs from baseline.",
                ))

    for name in t_map:
        if name not in b_map:
            result.extra_in_target.append({"section": section, key: name})


def _cmp_data_guard(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_dg = baseline.get("data-guard", {})
    t_dg = target.get("data-guard", {})
    if not b_dg:
        return

    b_enabled = b_dg.get("enabled", False)
    t_enabled = t_dg.get("enabled", False)

    if b_enabled and not t_enabled:
        _add(result, DiffItem(
            section="data-guard",
            element_name="data-guard",
            attribute="enabled",
            baseline_value=True,
            target_value=False,
            severity=SEVERITY_CRITICAL,
            description="Data Guard is enabled in baseline but DISABLED in target. "
                        "Sensitive data (PII) may be exposed in responses.",
        ))
        return  # No point comparing sub-settings if DG is off

    for attr in ("creditCardNumbers", "socialSecurityNumbers"):
        b_val = b_dg.get(attr)
        t_val = t_dg.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="data-guard",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=SEVERITY_CRITICAL if b_val else SEVERITY_WARNING,
                description=f"Data Guard {attr} protection differs from baseline.",
            ))


def _cmp_ip_intelligence(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_ip = baseline.get("ip-intelligence", {})
    t_ip = target.get("ip-intelligence", {})
    if not b_ip:
        return

    if b_ip.get("enabled") and not t_ip.get("enabled"):
        _add(result, DiffItem(
            section="ip-intelligence",
            element_name="ip-intelligence",
            attribute="enabled",
            baseline_value=True,
            target_value=False,
            severity=SEVERITY_CRITICAL,
            description="IP Intelligence is enabled in baseline but disabled in target.",
        ))
        return

    b_cats = {c["name"]: c for c in b_ip.get("categories", [])}
    t_cats = {c["name"]: c for c in t_ip.get("categories", [])}

    for name, b_cat in b_cats.items():
        if name not in t_cats:
            result.missing_in_target.append(
                {"section": "ip-intelligence.categories", "name": name}
            )
            continue
        t_cat = t_cats[name]
        for attr in ("alarm", "block"):
            b_val = b_cat.get(attr)
            t_val = t_cat.get(attr)
            if b_val != t_val:
                sev = (
                    SEVERITY_CRITICAL
                    if attr == "block" and b_val and not t_val
                    else SEVERITY_WARNING
                )
                _add(result, DiffItem(
                    section="ip-intelligence.categories",
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=f"IP Intelligence category '{name}' {attr} differs from baseline.",
                ))


def _cmp_bot_defense(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_bd = baseline.get("bot-defense", {})
    t_bd = target.get("bot-defense", {})
    if not b_bd:
        return

    if b_bd.get("enabled") and not t_bd.get("enabled"):
        _add(result, DiffItem(
            section="bot-defense",
            element_name="bot-defense",
            attribute="enabled",
            baseline_value=True,
            target_value=False,
            severity=SEVERITY_CRITICAL,
            description="Bot Defense is enabled in baseline but disabled in target.",
        ))


def _cmp_whitelist_ips(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    b_ips = {f"{ip['ipAddress']}/{ip['ipMask']}": ip
             for ip in baseline.get("whitelist-ips", [])}
    t_ips = {f"{ip['ipAddress']}/{ip['ipMask']}": ip
             for ip in target.get("whitelist-ips", [])}

    # IPs in target but not in baseline → WARNING (unauthorized)
    for cidr in t_ips:
        if cidr not in b_ips:
            _add(result, DiffItem(
                section="whitelist-ips",
                element_name=cidr,
                attribute="ipAddress",
                baseline_value="not present",
                target_value=cidr,
                severity=SEVERITY_WARNING,
                description=f"IP/CIDR {cidr} is whitelisted in target but not in baseline. "
                            "Potentially unauthorized exception.",
            ))
            result.extra_in_target.append({"section": "whitelist-ips", "ip": cidr})

    # IPs in baseline but not in target → INFO
    for cidr in b_ips:
        if cidr not in t_ips:
            _add(result, DiffItem(
                section="whitelist-ips",
                element_name=cidr,
                attribute="ipAddress",
                baseline_value=cidr,
                target_value="not present",
                severity=SEVERITY_INFO,
                description=f"IP/CIDR {cidr} is in baseline whitelist but missing from target.",
            ))
            result.missing_in_target.append({"section": "whitelist-ips", "ip": cidr})


# ── Score & summary ────────────────────────────────────────────────────────────

def _calculate_score(diffs: List[DiffItem]) -> float:
    deduction = sum(_DEDUCT.get(d.severity, 0) for d in diffs)
    return max(0.0, round(100.0 - deduction, 1))


def _build_summary(result: ComparisonResult) -> None:
    """Populate result.summary with per-section and per-severity counts."""
    from collections import defaultdict
    by_section: Dict[str, Dict[str, int]] = defaultdict(lambda: {"critical": 0, "warning": 0, "info": 0, "total": 0})

    for diff in result.diffs:
        section = diff.section.split('.')[0]
        by_section[section][diff.severity] += 1
        by_section[section]["total"] += 1

    totals = {"critical": 0, "warning": 0, "info": 0, "total": 0}
    for counts in by_section.values():
        for k in totals:
            totals[k] += counts[k]

    result.summary = {
        "by_section": dict(by_section),
        "totals": totals,
        "missing_count": len(result.missing_in_target),
        "extra_count":   len(result.extra_in_target),
    }
