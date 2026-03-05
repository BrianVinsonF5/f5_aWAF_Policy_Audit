"""
Report generation: Markdown and self-contained HTML output.
"""
from __future__ import annotations

import html as _html_module
from pathlib import Path
from typing import List, Optional

from .policy_comparator import ComparisonResult, DiffItem, SEVERITY_CRITICAL, SEVERITY_WARNING
from .utils import get_logger, ensure_dir, human_bool

_log = get_logger("report_generator")

_PASS_THRESHOLD = 90.0

# ── Policy Builder display config ──────────────────────────────────────────────

# (section_label, display_name, flat_key)
_PB_FLAT_ROWS = [
    ("Core", "Learning Mode",                   "learningMode"),
    ("Core", "Fully Automatic",                 "fullyAutomatic"),
    ("Core", "Client-Side Policy Building",     "clientSidePolicyBuilding"),
    ("Core", "Learn From Responses",            "learnFromResponses"),
    ("Core", "Learn Inactive Entities",         "learnInactiveEntities"),
    ("Core", "Enable Full Policy Inspection",   "enableFullPolicyInspection"),
    ("Core", "Auto Apply Frequency",            "autoApplyFrequency"),
    ("Core", "Auto Apply Start Time",           "autoApplyStartTime"),
    ("Core", "Auto Apply End Time",             "autoApplyEndTime"),
    ("Core", "Apply on All Days",               "applyOnAllDays"),
    ("Core", "Apply at All Times",              "applyAtAllTimes"),
    ("Core", "Learn Only from Non-Bot Traffic", "learnOnlyFromNonBotTraffic"),
    ("Core", "All Trusted IPs Source",          "allTrustedIps"),
    ("Core", "Response Codes",                  "responseCodes"),
]

# (section_label, display_name, sub_key, field_key)
_PB_SUB_ROWS = [
    ("Cookie",                  "Learn Cookies",               "cookie",                   "learnCookies"),
    ("Cookie",                  "Max Modified Cookies",        "cookie",                   "maximumAllowedModifiedCookies"),
    ("Cookie",                  "Collapse Cookies",            "cookie",                   "collapseCookies"),
    ("Cookie",                  "Enforce Unmodified Cookies",  "cookie",                   "enforceUnmodifiedCookies"),
    ("File Type",               "Learn File Types",            "filetype",                 "learnFileTypes"),
    ("File Type",               "Maximum File Types",          "filetype",                 "maximumFileTypes"),
    ("Parameter",               "Learn Parameters",            "parameter",                "learnParameters"),
    ("Parameter",               "Maximum Parameters",          "parameter",                "maximumParameters"),
    ("Parameter",               "Parameter Level",             "parameter",                "parameterLevel"),
    ("Parameter",               "Collapse Parameters",         "parameter",                "collapseParameters"),
    ("Parameter",               "Classify Parameters",         "parameter",                "classifyParameters"),
    ("URL",                     "Learn URLs",                  "url",                      "learnUrls"),
    ("URL",                     "Learn WebSocket URLs",        "url",                      "learnWebsocketUrls"),
    ("URL",                     "Maximum URLs",                "url",                      "maximumUrls"),
    ("URL",                     "Collapse URLs",               "url",                      "collapseUrls"),
    ("URL",                     "Classify URLs",               "url",                      "classifyUrls"),
    ("Header",                  "Valid Host Names",            "header",                   "validHostNames"),
    ("Header",                  "Maximum Hosts",               "header",                   "maximumHosts"),
    ("Redirection Protection",  "Learn Redirection Domains",   "redirectionProtection",    "learnRedirectionDomains"),
    ("Redirection Protection",  "Max Redirection Domains",     "redirectionProtection",    "maximumRedirectionDomains"),
    ("Sessions & Logins",       "Learn Login Pages",           "sessionsAndLogins",        "learnLoginPages"),
    ("Server Technologies",     "Learn Server Technologies",   "serverTechnologies",       "learnServerTechnologies"),
    ("Central Configuration",   "Building Mode",               "centralConfiguration",     "buildingMode"),
    ("Central Configuration",   "Event Correlation Mode",      "centralConfiguration",     "eventCorrelationMode"),
]


# ── Markdown ───────────────────────────────────────────────────────────────────

def generate_markdown(result: ComparisonResult, output_dir: str) -> Path:
    """Write a Markdown audit report. Returns the file path."""
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    safe_name = result.policy_name.replace('/', '_').replace(' ', '_')
    out_path = reports_dir / f"{safe_name}_audit_report.md"

    lines: List[str] = []
    _md_header(lines, result)
    _md_policy_builder_status(lines, result)
    _md_violations_table(lines, result)
    _md_summary_table(lines, result)
    _md_findings(lines, result)
    _md_blocking_comparison(lines, result)
    _md_extra_missing(lines, result)

    out_path.write_text('\n'.join(lines), encoding='utf-8')
    _log.info("Markdown report: %s", out_path)
    return out_path


def _md_header(lines: List[str], result: ComparisonResult) -> None:
    score = result.score
    status = "PASS" if score >= _PASS_THRESHOLD else "FAIL"
    lines += [
        "# WAF Policy Compliance Audit Report",
        "",
        f"## Policy: `{result.policy_path}`",
        "",
        f"- **Partition:** {result.partition}",
        f"- **Enforcement Mode:** {result.enforcement_mode}",
        f"- **Baseline Policy:** {result.baseline_name}",
        f"- **Audit Date:** {result.timestamp}",
        f"- **Compliance Score:** {score:.1f}% — **{status}** (threshold: {_PASS_THRESHOLD:.0f}%)",
        "",
    ]
    # Virtual server bindings
    vs_list = result.virtual_servers
    lines.append("### Virtual Server Bindings")
    lines.append("")
    if vs_list:
        lines.append("| Virtual Server | IP Address | Port | Local Traffic Policies |")
        lines.append("|----------------|:----------:|:----:|------------------------|")
        for vs in vs_list:
            ltm_names = ", ".join(
                f"`{p.get('fullPath', p.get('name', ''))}`"
                for p in vs.get("ltm_policies", [])
            ) or "*(none)*"
            lines.append(
                f"| `{vs.get('fullPath', vs.get('name', ''))}` "
                f"| {vs.get('ip', '—')} "
                f"| {vs.get('port', '—')} "
                f"| {ltm_names} |"
            )
        lines.append("")

        # Per-VS LTM policy rule detail
        for vs in vs_list:
            for ltp in vs.get("ltm_policies", []):
                rules = ltp.get("rules", [])
                if not rules:
                    continue
                vs_path = vs.get('fullPath', vs.get('name', ''))
                ltp_path = ltp.get('fullPath', ltp.get('name', ''))
                lines += [
                    f"#### LTM Policy `{ltp_path}` on `{vs_path}`",
                    "",
                    "| Rule | Host Condition(s) | WAF Security Policy |",
                    "|------|:-----------------:|---------------------|",
                ]
                for rule in rules:
                    hosts = ", ".join(
                        f"`{h}`" for h in rule.get("host_conditions", [])
                    ) or "*(any)*"
                    waf = f"`{rule['waf_policy']}`" if rule.get("waf_policy") else "*(none)*"
                    lines.append(
                        f"| `{rule.get('name', '')}` | {hosts} | {waf} |"
                    )
                lines.append("")
    else:
        lines += [
            "*No virtual server bindings found for this policy.*",
            "",
        ]


def _md_policy_builder_status(lines: List[str], result: ComparisonResult) -> None:
    pb_t = result.policy_builder_target
    pb_b = result.policy_builder_baseline

    if not pb_t:
        return

    learning_mode = pb_t.get("learningMode", "unknown")
    bl_learning_mode = pb_b.get("learningMode", "") if pb_b else ""

    # Mode label + indicator
    mode_upper = learning_mode.upper()
    if learning_mode.lower() in ("automatic", "automatic-only"):
        mode_indicator = "✅ AUTOMATIC"
    elif learning_mode.lower() == "manual":
        mode_indicator = "⚠ MANUAL"
    elif learning_mode.lower() in ("disabled", ""):
        mode_indicator = "🔴 DISABLED"
    else:
        mode_indicator = f"ℹ {mode_upper}"

    differs = bl_learning_mode and bl_learning_mode.lower() != learning_mode.lower()
    baseline_note = f" *(Baseline: `{bl_learning_mode}`)*" if differs else ""

    lines += [
        "## Policy Builder Status",
        "",
        f"**Learning Mode:** `{learning_mode}` — **{mode_indicator}**{baseline_note}",
        "",
    ]

    # Full comparison table
    lines += [
        "### Policy Builder Settings",
        "",
        "| Section | Setting | Baseline | Target | Match |",
        "|---------|---------|----------|--------|-------|",
    ]

    def _fmt(val) -> str:
        if val is None or val == "":
            return "*(n/a)*"
        if isinstance(val, list):
            return ", ".join(str(v) for v in val) if val else "*(empty)*"
        return human_bool(val)

    def _match(b_val, t_val) -> str:
        if b_val is None or b_val == "":
            return "—"
        return "✓" if b_val == t_val else "⚠"

    for section, label, key in _PB_FLAT_ROWS:
        t_val = pb_t.get(key)
        b_val = pb_b.get(key) if pb_b else None
        lines.append(
            f"| {section} | {label} | {_fmt(b_val)} | {_fmt(t_val)} | {_match(b_val, t_val)} |"
        )

    for section, label, sub_key, field_key in _PB_SUB_ROWS:
        t_val = pb_t.get(sub_key, {}).get(field_key)
        b_val = pb_b.get(sub_key, {}).get(field_key) if pb_b else None
        lines.append(
            f"| {section} | {label} | {_fmt(b_val)} | {_fmt(t_val)} | {_match(b_val, t_val)} |"
        )

    lines.append("")


def _md_summary_table(lines: List[str], result: ComparisonResult) -> None:
    lines += [
        "## Executive Summary",
        "",
        "| Category | Critical | Warning | Info | Total |",
        "|----------|----------|---------|------|-------|",
    ]
    for section, counts in sorted(result.summary.get("by_section", {}).items()):
        lines.append(
            f"| {section} | {counts['critical']} | {counts['warning']} | {counts['info']} | {counts['total']} |"
        )
    totals = result.summary.get("totals", {})
    lines += [
        f"| **Totals** | **{totals.get('critical',0)}** | **{totals.get('warning',0)}** | **{totals.get('info',0)}** | **{totals.get('total',0)}** |",
        "",
        f"- **Missing elements (in baseline, absent in target):** {result.summary.get('missing_count', 0)}",
        f"- **Extra elements (in target, not in baseline):** {result.summary.get('extra_count', 0)}",
        "",
    ]


def _md_findings(lines: List[str], result: ComparisonResult) -> None:
    for sev_label, sev_key in [
        ("Critical Findings (Protections Disabled)", SEVERITY_CRITICAL),
        ("Warning Findings (Configuration Drift)",   SEVERITY_WARNING),
        ("Informational Findings",                   "info"),
    ]:
        items = [d for d in result.diffs if d.severity == sev_key]
        if not items:
            continue
        lines.append(f"## {sev_label}")
        lines.append("")
        for i, diff in enumerate(items, 1):
            lines += [
                f"### {i}. {diff.section}: {diff.element_name}",
                f"- **Attribute:** `{diff.attribute}`",
                f"- **Baseline:** {human_bool(diff.baseline_value)}",
                f"- **This Policy:** {human_bool(diff.target_value)}",
                f"- **Impact:** {diff.description}",
                "",
            ]


def _md_violations_table(lines: List[str], result: ComparisonResult) -> None:
    if not result.violations:
        return

    # Detect whether violations come from the richer <blocking> section (have 'id')
    has_id = any(v.get("id") for v in result.violations)

    # Build baseline lookup: keyed by id (falling back to name)
    baseline_map: dict = {}
    for bv in result.baseline_violations:
        key = bv.get("id") or bv.get("name", "")
        if key:
            baseline_map[key] = bv

    lines += ["## WAF Violations Status", ""]

    _MATCH = "✓ Match"
    _MISMATCH = "✗ Mismatch"
    _NO_BASELINE = "— N/A"

    def _baseline_match_md(v: dict, bv: dict | None) -> tuple[str, str]:
        """Return (match_cell, baseline_settings_cell) for markdown."""
        if bv is None:
            return _NO_BASELINE, "*(not in baseline)*"
        attrs = ["alarm", "block", "learn"]
        differs = any(v.get(a) != bv.get(a) for a in attrs)
        match_cell = _MISMATCH if differs else _MATCH
        bl_settings = (
            f"A:{human_bool(bv.get('alarm', False))} "
            f"B:{human_bool(bv.get('block', False))} "
            f"L:{human_bool(bv.get('learn', False))}"
        )
        return match_cell, bl_settings

    if has_id:
        lines += [
            "| ID | Violation Name | Alarm | Block | Learn | PB Tracking | Matches Baseline | Baseline (A/B/L) |",
            "|----|----------------|:-----:|:-----:|:-----:|:-----------:|:----------------:|:----------------:|",
        ]
        for v in sorted(result.violations, key=lambda x: x.get("id", x.get("name", ""))):
            vid = v.get("id") or v.get("name", "")
            bv = baseline_map.get(vid)
            match_cell, bl_settings = _baseline_match_md(v, bv)
            pb = human_bool(v.get("policyBuilderTracking", False))
            lines.append(
                f"| `{v.get('id', '')}` "
                f"| {v.get('name', '')} "
                f"| {human_bool(v.get('alarm', False))} "
                f"| {human_bool(v.get('block', False))} "
                f"| {human_bool(v.get('learn', False))} "
                f"| {pb} "
                f"| {match_cell} "
                f"| {bl_settings} |"
            )
    else:
        lines += [
            "| Violation | Alarm | Block | Learn | Matches Baseline | Baseline (A/B/L) |",
            "|-----------|:-----:|:-----:|:-----:|:----------------:|:----------------:|",
        ]
        for v in sorted(result.violations, key=lambda x: x.get("name", "")):
            vname = v.get("name", "")
            bv = baseline_map.get(vname)
            match_cell, bl_settings = _baseline_match_md(v, bv)
            lines.append(
                f"| {vname} "
                f"| {human_bool(v.get('alarm', False))} "
                f"| {human_bool(v.get('block', False))} "
                f"| {human_bool(v.get('learn', False))} "
                f"| {match_cell} "
                f"| {bl_settings} |"
            )

    lines.append("")


def _md_blocking_comparison(lines: List[str], result: ComparisonResult) -> None:
    """Render a side-by-side baseline-vs-target table for <blocking> violations."""
    blocking_diffs = [d for d in result.diffs if d.section == "blocking"]
    if not blocking_diffs and not result.violations:
        return

    # Build a map of violation id → list of diff attributes for quick lookup
    diff_by_id: dict = {}
    for d in blocking_diffs:
        if d.element_name not in ("enforcement_mode",):
            diff_by_id.setdefault(d.element_name, []).append(d)

    lines += [
        "## Blocking Section — Violations Comparison",
        "",
        "Compares each violation's Alarm / Block / Learn flags against the baseline.",
        "Cells marked with ⚠ differ from baseline; 🚨 indicates a critical security gap.",
        "",
        "| ID | Violation Name | Attr | Baseline | Target | Severity |",
        "|----|----------------|------|:--------:|:------:|----------|",
    ]

    if not blocking_diffs:
        lines += ["| — | *(no differences detected)* | — | — | — | — |", ""]
        return

    for d in blocking_diffs:
        icon = "🚨" if d.severity == SEVERITY_CRITICAL else "⚠"
        name = d.element_name
        # Try to resolve display name from violations list
        for v in result.violations:
            if (v.get("id") or v.get("name")) == d.element_name:
                name = v.get("name", d.element_name)
                break
        lines.append(
            f"| `{d.element_name}` "
            f"| {name} "
            f"| `{d.attribute}` "
            f"| {human_bool(d.baseline_value)} "
            f"| {human_bool(d.target_value)} "
            f"| {icon} {d.severity.upper()} |"
        )
    lines.append("")


def _md_extra_missing(lines: List[str], result: ComparisonResult) -> None:
    if result.extra_in_target:
        lines.append("## Extra Elements Not in Baseline")
        lines.append("")
        lines.append("Items present in this policy but not in the baseline:")
        lines.append("")
        for item in result.extra_in_target:
            lines.append(f"- `{item}`")
        lines.append("")

    if result.missing_in_target:
        lines.append("## Missing Elements From Baseline")
        lines.append("")
        lines.append("Items expected from baseline that are absent in this policy:")
        lines.append("")
        for item in result.missing_in_target:
            lines.append(f"- `{item}`")
        lines.append("")


# ── HTML ───────────────────────────────────────────────────────────────────────

_CSS = """
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Arial,Helvetica,sans-serif;background:#f5f6f8;color:#333;padding:20px}
h1{color:#1a1a2e;margin-bottom:8px}
h2{color:#16213e;margin:24px 0 8px;border-bottom:2px solid #e0e0e0;padding-bottom:4px}
h3{color:#0f3460;margin:14px 0 6px}
.meta{background:#fff;border-radius:6px;padding:16px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.meta table{border-collapse:collapse;width:100%}
.meta td{padding:4px 10px;vertical-align:top}
.meta td:first-child{font-weight:bold;color:#555;width:220px}
.score-bar{height:24px;border-radius:4px;background:#e0e0e0;overflow:hidden;margin:6px 0}
.score-fill{height:100%;transition:width .4s}
.score-pass{background:#28a745}
.score-fail{background:#dc3545}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:.8em;font-weight:bold;color:#fff}
.badge-critical{background:#dc3545}
.badge-warning{background:#fd7e14}
.badge-info{background:#17a2b8}
.badge-pass{background:#28a745}
.badge-fail{background:#dc3545}
.badge-manual{background:#fd7e14}
.badge-automatic{background:#28a745}
.badge-disabled{background:#dc3545}
.badge-unknown{background:#6c757d}
.pb-banner{border-radius:6px;padding:14px 18px;margin:16px 0;display:flex;align-items:center;gap:14px;font-size:1em}
.pb-banner-manual{background:#fff3cd;border:1px solid #ffc107}
.pb-banner-automatic{background:#d4edda;border:1px solid #28a745}
.pb-banner-disabled{background:#f8d7da;border:1px solid #dc3545}
.pb-banner-unknown{background:#e2e3e5;border:1px solid #adb5bd}
.pb-banner .pb-mode-label{font-size:1.1em;font-weight:bold}
.pb-banner .pb-baseline-note{font-size:.85em;color:#555;margin-left:6px}
table.findings{width:100%;border-collapse:collapse;margin:8px 0;font-size:.9em}
table.findings th{background:#1a1a2e;color:#fff;padding:8px 10px;text-align:left}
table.findings td{padding:7px 10px;border-bottom:1px solid #e0e0e0;vertical-align:top}
table.findings tr:nth-child(even){background:#f9f9f9}
table.findings tr:hover{background:#eef3ff}
table.findings td.match-ok{color:#28a745;font-weight:bold;text-align:center}
table.findings td.match-diff{color:#dc3545;font-weight:bold;text-align:center}
table.findings td.match-na{color:#aaa;text-align:center}
.summary-table{width:100%;border-collapse:collapse;margin:8px 0}
.summary-table th{background:#16213e;color:#fff;padding:8px 10px}
.summary-table td{padding:7px 10px;border-bottom:1px solid #e0e0e0;text-align:center}
.summary-table td:first-child{text-align:left}
details{background:#fff;border:1px solid #ddd;border-radius:6px;margin:10px 0;padding:0}
summary{padding:12px 16px;cursor:pointer;font-weight:bold;color:#16213e;list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:"▶";font-size:.8em;transition:transform .2s}
details[open] summary::before{transform:rotate(90deg)}
.details-body{padding:4px 16px 16px}
.list-items li{padding:3px 0;font-family:monospace;font-size:.85em}
@media print{
  .score-bar{-webkit-print-color-adjust:exact}
  .pb-banner{-webkit-print-color-adjust:exact}
  details{display:block}
  details summary::before{display:none}
}
</style>
"""

def _e(text) -> str:
    """HTML-escape a value."""
    return _html_module.escape(str(text))


def generate_html(result: ComparisonResult, output_dir: str) -> Path:
    """Write a self-contained HTML audit report. Returns the file path."""
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    safe_name = result.policy_name.replace('/', '_').replace(' ', '_')
    out_path = reports_dir / f"{safe_name}_audit_report.html"

    score = result.score
    pass_fail = "PASS" if score >= _PASS_THRESHOLD else "FAIL"
    score_class = "score-pass" if score >= _PASS_THRESHOLD else "score-fail"
    badge_pf = f'<span class="badge badge-{pass_fail.lower()}">{pass_fail}</span>'

    # Build virtual server rows for the meta table
    vs_list = result.virtual_servers
    if vs_list:
        vs_rows = []
        for vs in vs_list:
            vs_name = _e(vs.get('fullPath', vs.get('name', '')))
            vs_ip   = _e(vs.get('ip', '—'))
            vs_port = _e(vs.get('port', '—'))
            ltm_policies = vs.get("ltm_policies", [])
            ltm_cell = (
                ", ".join(f"<code>{_e(p.get('fullPath', p.get('name','')))}</code>"
                          for p in ltm_policies)
                if ltm_policies else "<em>none</em>"
            )
            vs_rows.append(
                f"<tr>"
                f"<td style='padding-left:20px'>&#8627; <code>{vs_name}</code></td>"
                f"<td>{vs_ip}:{vs_port}</td>"
                f"<td>{ltm_cell}</td>"
                f"</tr>"
            )
        vs_html = (
            f"<tr><td>Virtual Server Bindings</td><td>"
            f"<table style='width:100%;border-collapse:collapse'>"
            f"<thead><tr>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Name</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>IP:Port</th>"
            f"<th style='text-align:left;font-weight:normal;color:#555'>Local Traffic Policies</th>"
            f"</tr></thead><tbody>"
            + "".join(vs_rows) +
            f"</tbody></table></td></tr>"
        )
    else:
        vs_html = "<tr><td>Virtual Server Bindings</td><td><em>None found</em></td></tr>"

    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>",
        f"<title>WAF Audit: {_e(result.policy_path)}</title>",
        _CSS,
        "</head><body>",
        f"<h1>WAF Policy Compliance Audit Report</h1>",
        "<div class='meta'>",
        "<table>",
        f"<tr><td>Policy</td><td><code>{_e(result.policy_path)}</code></td></tr>",
        f"<tr><td>Partition</td><td>{_e(result.partition)}</td></tr>",
        f"<tr><td>Enforcement Mode</td><td>{_e(result.enforcement_mode)}</td></tr>",
        vs_html,
        f"<tr><td>Baseline Policy</td><td>{_e(result.baseline_name)}</td></tr>",
        f"<tr><td>Audit Date</td><td>{_e(result.timestamp)}</td></tr>",
        f"<tr><td>Compliance Score</td><td><strong>{score:.1f}%</strong> {badge_pf}</td></tr>",
        "</table>",
        f"<div class='score-bar'><div class='{score_class} score-fill' style='width:{min(score,100):.1f}%'></div></div>",
        "</div>",
    ]

    # LTM policy rule detail (collapsible, after the meta block)
    ltm_section = _html_ltm_policy_section(vs_list)
    if ltm_section:
        parts.append(ltm_section)

    # Policy Builder status banner + settings table
    parts.append(_html_policy_builder_status(result))

    # WAF Violations Status — collapsible, directly after Policy Builder
    if result.violations:
        parts.append(
            "<details><summary><h2 style='display:inline;font-size:1em'>"
            f"WAF Violations Status ({len(result.violations)})</h2></summary>"
            "<div class='details-body'>"
        )
        parts.append(_html_violations_table(result.violations, result.baseline_violations))
        parts.append("</div></details>")

    # Executive summary
    parts.append("<h2>Executive Summary</h2>")
    parts.append(_html_summary_table(result))

    # Findings per severity
    for sev_label, sev_key, badge_cls in [
        ("Critical Findings", SEVERITY_CRITICAL, "critical"),
        ("Warning Findings",  SEVERITY_WARNING,  "warning"),
        ("Informational Findings", "info",        "info"),
    ]:
        items = [d for d in result.diffs if d.severity == sev_key]
        if not items:
            continue
        parts.append(
            f"<details open><summary>"
            f"<span class='badge badge-{badge_cls}'>{sev_label}</span>"
            f"&nbsp;({len(items)})</summary>"
            f"<div class='details-body'>"
        )
        parts.append(_html_findings_table(items))
        parts.append("</div></details>")

    # Blocking violations comparison — collapsible
    blocking_diffs = [d for d in result.diffs if d.section == "blocking"]
    if blocking_diffs or result.violations:
        n = len(blocking_diffs)
        parts.append(
            f"<details><summary><h2 style='display:inline;font-size:1em'>"
            f"Blocking Section — Violations Comparison ({n} diff{'s' if n != 1 else ''})</h2>"
            f"</summary><div class='details-body'>"
            f"<p style='margin:8px 0'>Each violation's Alarm / Block / Learn flags compared against the baseline.</p>"
        )
        parts.append(_html_blocking_comparison_table(blocking_diffs, result.violations))
        parts.append("</div></details>")

    # Extra / missing
    if result.extra_in_target:
        parts.append("<details><summary>Extra Elements Not in Baseline "
                     f"({len(result.extra_in_target)})</summary>"
                     "<div class='details-body'><ul class='list-items'>")
        for item in result.extra_in_target:
            parts.append(f"<li>{_e(str(item))}</li>")
        parts.append("</ul></div></details>")

    if result.missing_in_target:
        parts.append("<details><summary>Missing Elements From Baseline "
                     f"({len(result.missing_in_target)})</summary>"
                     "<div class='details-body'><ul class='list-items'>")
        for item in result.missing_in_target:
            parts.append(f"<li>{_e(str(item))}</li>")
        parts.append("</ul></div></details>")

    parts.append("</body></html>")

    out_path.write_text('\n'.join(parts), encoding='utf-8')
    _log.info("HTML report: %s", out_path)
    return out_path


def _html_summary_table(result: ComparisonResult) -> str:
    rows = []
    for section, counts in sorted(result.summary.get("by_section", {}).items()):
        rows.append(
            f"<tr><td>{_e(section)}</td>"
            f"<td>{counts['critical']}</td>"
            f"<td>{counts['warning']}</td>"
            f"<td>{counts['info']}</td>"
            f"<td>{counts['total']}</td></tr>"
        )
    totals = result.summary.get("totals", {})
    rows.append(
        f"<tr style='font-weight:bold'><td>Totals</td>"
        f"<td>{totals.get('critical',0)}</td>"
        f"<td>{totals.get('warning',0)}</td>"
        f"<td>{totals.get('info',0)}</td>"
        f"<td>{totals.get('total',0)}</td></tr>"
    )
    return (
        "<table class='summary-table'>"
        "<thead><tr><th>Category</th><th>Critical</th><th>Warning</th><th>Info</th><th>Total</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _html_ltm_policy_section(vs_list: List[Dict]) -> str:
    """
    Render a collapsible HTML section showing LTM policy rules for all
    virtual servers that have Local Traffic Policies attached.

    Each rule row shows: rule name | host condition(s) | WAF security policy.
    Returns an empty string when there are no LTM policies to display.
    """
    # Collect (vs_path, ltp_path, [rules]) tuples that have content
    entries = []
    for vs in vs_list:
        for ltp in vs.get("ltm_policies", []):
            rules = ltp.get("rules", [])
            if rules:
                entries.append((
                    vs.get("fullPath", vs.get("name", "")),
                    ltp.get("fullPath", ltp.get("name", "")),
                    rules,
                ))

    if not entries:
        return ""

    total_rules = sum(len(e[2]) for e in entries)
    parts = [
        f"<details open><summary>"
        f"<h2 style='display:inline;font-size:1em'>"
        f"Local Traffic Policy — Host-to-WAF Mappings ({total_rules} rule{'s' if total_rules != 1 else ''})"
        f"</h2></summary>"
        f"<div class='details-body'>"
        f"<p style='margin:8px 0'>Rules from LTM policies that map host conditions "
        f"to WAF security policies on each virtual server.</p>"
    ]

    for vs_path, ltp_path, rules in entries:
        rows = []
        for rule in rules:
            hosts = rule.get("host_conditions", [])
            host_cell = (
                " ".join(f"<code>{_e(h)}</code>" for h in hosts)
                if hosts else "<em>any</em>"
            )
            waf = rule.get("waf_policy", "")
            waf_cell = f"<code>{_e(waf)}</code>" if waf else "<em style='color:#999'>none</em>"
            rows.append(
                f"<tr>"
                f"<td><code>{_e(rule.get('name', ''))}</code></td>"
                f"<td>{host_cell}</td>"
                f"<td>{waf_cell}</td>"
                f"</tr>"
            )

        parts.append(
            f"<h3 style='margin:14px 0 4px'>"
            f"<code>{_e(ltp_path)}</code>"
            f" <span style='font-weight:normal;font-size:.85em;color:#555'>"
            f"on <code>{_e(vs_path)}</code></span></h3>"
            f"<table class='findings'>"
            f"<thead><tr>"
            f"<th>Rule</th><th>Host Condition(s)</th><th>WAF Security Policy</th>"
            f"</tr></thead><tbody>"
            + "".join(rows) +
            f"</tbody></table>"
        )

    parts.append("</div></details>")
    return "".join(parts)


def _html_policy_builder_status(result: ComparisonResult) -> str:
    pb_t = result.policy_builder_target
    pb_b = result.policy_builder_baseline

    if not pb_t:
        return ""

    learning_mode = pb_t.get("learningMode", "unknown")
    bl_learning_mode = pb_b.get("learningMode", "") if pb_b else ""
    mode_lc = learning_mode.lower()

    if mode_lc in ("automatic", "automatic-only"):
        banner_cls, badge_cls, icon = "pb-banner-automatic", "badge-automatic", "&#10003;"
    elif mode_lc == "manual":
        banner_cls, badge_cls, icon = "pb-banner-manual",    "badge-manual",    "&#9888;"
    elif mode_lc in ("disabled", ""):
        banner_cls, badge_cls, icon = "pb-banner-disabled",  "badge-disabled",  "&#10007;"
    else:
        banner_cls, badge_cls, icon = "pb-banner-unknown",   "badge-unknown",   "&#8505;"

    differs = bl_learning_mode and bl_learning_mode.lower() != mode_lc
    baseline_note = (
        f"<span class='pb-baseline-note'>(Baseline: <code>{_e(bl_learning_mode)}</code>)</span>"
        if differs else ""
    )

    banner = (
        f"<h2>Policy Builder Status</h2>"
        f"<div class='pb-banner {_e(banner_cls)}'>"
        f"<span class='badge {_e(badge_cls)}'>{icon} {_e(learning_mode.upper())}</span>"
        f"<span class='pb-mode-label'>Learning Mode: <strong>{_e(learning_mode)}</strong></span>"
        f"{baseline_note}"
        f"</div>"
    )

    # Settings comparison table
    def _fmt(val) -> str:
        if val is None or val == "":
            return "<em>n/a</em>"
        if isinstance(val, list):
            return _e(", ".join(str(v) for v in val)) if val else "<em>empty</em>"
        return _e(human_bool(val))

    rows = []
    last_section = None

    all_rows = (
        [(sec, label, pb_t.get(key), pb_b.get(key) if pb_b else None)
         for sec, label, key in _PB_FLAT_ROWS]
        +
        [(sec, label, pb_t.get(sub, {}).get(fld), pb_b.get(sub, {}).get(fld) if pb_b else None)
         for sec, label, sub, fld in _PB_SUB_ROWS]
    )

    for section, label, t_val, b_val in all_rows:
        if section != last_section:
            rows.append(
                f"<tr style='background:#e8ecf5'>"
                f"<td colspan='4' style='font-weight:bold;color:#16213e;padding:6px 10px'>"
                f"{_e(section)}</td></tr>"
            )
            last_section = section

        if b_val is None or b_val == "":
            match_td = "<td class='match-na'>—</td>"
        elif b_val == t_val:
            match_td = "<td class='match-ok'>&#10003;</td>"
        else:
            match_td = "<td class='match-diff'>&#9888;</td>"

        rows.append(
            f"<tr>"
            f"<td>{_e(label)}</td>"
            f"<td>{_fmt(b_val)}</td>"
            f"<td>{_fmt(t_val)}</td>"
            f"{match_td}"
            f"</tr>"
        )

    table = (
        "<details open><summary>Policy Builder Settings Comparison</summary>"
        "<div class='details-body'>"
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Setting</th><th>Baseline</th><th>Target</th><th>Match</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table>"
        "</div></details>"
    )

    return banner + table


def _html_findings_table(diffs: List[DiffItem]) -> str:
    rows = []
    for diff in diffs:
        badge = f"<span class='badge badge-{_e(diff.severity)}'>{_e(diff.severity.upper())}</span>"
        rows.append(
            f"<tr>"
            f"<td>{_e(diff.section)}</td>"
            f"<td>{_e(diff.element_name)}</td>"
            f"<td><code>{_e(diff.attribute)}</code></td>"
            f"<td>{_e(human_bool(diff.baseline_value))}</td>"
            f"<td>{_e(human_bool(diff.target_value))}</td>"
            f"<td>{_e(diff.description)}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )
    return (
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Section</th><th>Element</th><th>Attribute</th>"
        "<th>Baseline</th><th>Target</th><th>Description</th><th>Severity</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _html_blocking_comparison_table(diffs: List[DiffItem], violations: List[dict]) -> str:
    """
    Render a side-by-side baseline-vs-target HTML table for <blocking> violations.
    Each row shows a single attribute difference for a specific violation id.
    """
    # Build id → display name lookup from violations list
    id_to_name = {}
    for v in violations:
        vid = v.get("id") or v.get("name", "")
        id_to_name[vid] = v.get("name", vid)

    if not diffs:
        return "<p><em>No differences detected in the blocking violations section.</em></p>"

    rows = []
    for d in diffs:
        sev_cls = d.severity
        badge = f"<span class='badge badge-{_e(sev_cls)}'>{_e(d.severity.upper())}</span>"
        display_name = id_to_name.get(d.element_name, d.element_name)
        rows.append(
            f"<tr>"
            f"<td><code>{_e(d.element_name)}</code></td>"
            f"<td>{_e(display_name)}</td>"
            f"<td><code>{_e(d.attribute)}</code></td>"
            f"<td>{_e(human_bool(d.baseline_value))}</td>"
            f"<td>{_e(human_bool(d.target_value))}</td>"
            f"<td>{_e(d.description)}</td>"
            f"<td>{badge}</td>"
            f"</tr>"
        )
    return (
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Violation ID</th><th>Name</th><th>Attribute</th>"
        "<th>Baseline</th><th>Target</th><th>Description</th><th>Severity</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


def _html_violations_table(violations: List[dict], baseline_violations: List[dict] | None = None) -> str:
    has_id = any(v.get("id") for v in violations)
    rows = []

    # Build baseline lookup
    baseline_map: dict = {}
    for bv in (baseline_violations or []):
        key = bv.get("id") or bv.get("name", "")
        if key:
            baseline_map[key] = bv

    def _flag_badge(val: bool) -> str:
        cls = "pass" if val else "fail"
        label = "Yes" if val else "No"
        return f"<span class='badge badge-{cls}'>{label}</span>"

    def _match_badge(v: dict, bv: dict | None) -> str:
        if bv is None:
            return "<span class='badge badge-info'>N/A</span>"
        attrs = ["alarm", "block", "learn"]
        differs = any(v.get(a) != bv.get(a) for a in attrs)
        if differs:
            return "<span class='badge badge-fail'>Mismatch</span>"
        return "<span class='badge badge-pass'>Match</span>"

    def _baseline_settings(bv: dict | None) -> str:
        if bv is None:
            return "<em>not in baseline</em>"
        return (
            f"A:{_flag_badge(bv.get('alarm', False))} "
            f"B:{_flag_badge(bv.get('block', False))} "
            f"L:{_flag_badge(bv.get('learn', False))}"
        )

    if has_id:
        for v in sorted(violations, key=lambda x: x.get("id", x.get("name", ""))):
            vid = v.get("id") or v.get("name", "")
            bv = baseline_map.get(vid)
            rows.append(
                f"<tr>"
                f"<td><code>{_e(v.get('id', ''))}</code></td>"
                f"<td>{_e(v.get('name', ''))}</td>"
                f"<td>{_flag_badge(v.get('alarm', False))}</td>"
                f"<td>{_flag_badge(v.get('block', False))}</td>"
                f"<td>{_flag_badge(v.get('learn', False))}</td>"
                f"<td>{_flag_badge(v.get('policyBuilderTracking', False))}</td>"
                f"<td>{_match_badge(v, bv)}</td>"
                f"<td>{_baseline_settings(bv)}</td>"
                f"</tr>"
            )
        return (
            "<table class='findings'>"
            "<thead><tr>"
            "<th>ID</th><th>Violation Name</th>"
            "<th>Alarm</th><th>Block</th><th>Learn</th><th>PB Tracking</th>"
            "<th>Matches Baseline</th><th>Baseline (A/B/L)</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    else:
        for v in sorted(violations, key=lambda x: x.get("name", "")):
            vname = v.get("name", "")
            bv = baseline_map.get(vname)
            rows.append(
                f"<tr>"
                f"<td>{_e(vname)}</td>"
                f"<td>{_flag_badge(v.get('alarm', False))}</td>"
                f"<td>{_flag_badge(v.get('block', False))}</td>"
                f"<td>{_flag_badge(v.get('learn', False))}</td>"
                f"<td>{_match_badge(v, bv)}</td>"
                f"<td>{_baseline_settings(bv)}</td>"
                f"</tr>"
            )
        return (
            "<table class='findings'>"
            "<thead><tr>"
            "<th>Violation</th><th>Alarm</th><th>Block</th><th>Learn</th>"
            "<th>Matches Baseline</th><th>Baseline (A/B/L)</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )


# ── Summary report ─────────────────────────────────────────────────────────────

def generate_summary_reports(
    results: List[ComparisonResult],
    output_dir: str,
    formats: List[str],
) -> None:
    """
    Generate a cross-policy summary report sorted by compliance score (worst first).
    """
    sorted_results = sorted(results, key=lambda r: r.score)
    reports_dir = ensure_dir(Path(output_dir) / "reports")

    if "markdown" in formats:
        _write_summary_md(sorted_results, reports_dir)
    if "html" in formats:
        _write_summary_html(sorted_results, reports_dir)


def _write_summary_md(results: List[ComparisonResult], reports_dir: Path) -> None:
    lines = [
        "# WAF Policy Audit — Summary Report",
        "",
        "Policies sorted by compliance score (lowest first).",
        "",
        "| Policy | Partition | Enforcement | Virtual Servers | Score | Status | Critical | Warning | Info |",
        "|--------|-----------|-------------|-----------------|-------|--------|----------|---------|------|",
    ]
    for r in results:
        status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
        totals = r.summary.get("totals", {})
        if r.virtual_servers:
            vs_cell = "<br>".join(
                f"`{vs.get('fullPath', vs.get('name', ''))}` ({vs.get('ip', '?')}:{vs.get('port', '?')})"
                for vs in r.virtual_servers
            )
        else:
            vs_cell = "*(none)*"
        lines.append(
            f"| `{r.policy_path}` | {r.partition} | {r.enforcement_mode} "
            f"| {vs_cell} "
            f"| {r.score:.1f}% | {status} "
            f"| {totals.get('critical',0)} | {totals.get('warning',0)} | {totals.get('info',0)} |"
        )
    out = reports_dir / "summary_audit_report.md"
    out.write_text('\n'.join(lines), encoding='utf-8')
    _log.info("Summary Markdown: %s", out)


def _write_summary_html(results: List[ComparisonResult], reports_dir: Path) -> None:
    rows = []
    for r in results:
        status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
        badge_cls = "pass" if status == "PASS" else "fail"
        totals = r.summary.get("totals", {})
        score_class = "score-pass" if r.score >= _PASS_THRESHOLD else "score-fail"

        if r.virtual_servers:
            vs_items = "".join(
                f"<div style='white-space:nowrap'>"
                f"<code>{_e(vs.get('fullPath', vs.get('name', '')))}</code>"
                f"&nbsp;<span style='color:#555;font-size:.85em'>"
                f"{_e(vs.get('ip', '?'))}:{_e(vs.get('port', '?'))}"
                f"</span></div>"
                for vs in r.virtual_servers
            )
            vs_cell = vs_items
        else:
            vs_cell = "<em style='color:#999'>none</em>"

        rows.append(
            f"<tr>"
            f"<td><code>{_e(r.policy_path)}</code></td>"
            f"<td>{_e(r.partition)}</td>"
            f"<td>{_e(r.enforcement_mode)}</td>"
            f"<td>{vs_cell}</td>"
            f"<td>"
            f"  <div class='score-bar'><div class='{score_class} score-fill' style='width:{min(r.score,100):.1f}%'></div></div>"
            f"  {r.score:.1f}%"
            f"</td>"
            f"<td><span class='badge badge-{badge_cls}'>{status}</span></td>"
            f"<td>{totals.get('critical',0)}</td>"
            f"<td>{totals.get('warning',0)}</td>"
            f"<td>{totals.get('info',0)}</td>"
            f"</tr>"
        )

    content = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
        "<title>WAF Audit Summary</title>"
        + _CSS +
        "</head><body>"
        "<h1>WAF Policy Audit — Summary Report</h1>"
        "<p>Policies sorted by compliance score (lowest first).</p>"
        "<table class='summary-table findings'>"
        "<thead><tr>"
        "<th>Policy</th><th>Partition</th><th>Enforcement</th>"
        "<th>Virtual Servers</th>"
        "<th>Score</th><th>Status</th><th>Critical</th><th>Warning</th><th>Info</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table></body></html>"
    )
    out = reports_dir / "summary_audit_report.html"
    out.write_text(content, encoding='utf-8')
    _log.info("Summary HTML: %s", out)
