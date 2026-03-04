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


# ── Markdown ───────────────────────────────────────────────────────────────────

def generate_markdown(result: ComparisonResult, output_dir: str) -> Path:
    """Write a Markdown audit report. Returns the file path."""
    reports_dir = ensure_dir(Path(output_dir) / "reports")
    safe_name = result.policy_name.replace('/', '_').replace(' ', '_')
    out_path = reports_dir / f"{safe_name}_audit_report.md"

    lines: List[str] = []
    _md_header(lines, result)
    _md_summary_table(lines, result)
    _md_findings(lines, result)
    _md_violations_table(lines, result)
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
    lines += [
        "## WAF Violations Status",
        "",
        "| Violation | Enabled | Learn | Alarm | Block |",
        "|-----------|:-------:|:-----:|:-----:|:-----:|",
    ]
    for v in sorted(result.violations, key=lambda x: x.get("name", "")):
        lines.append(
            f"| {v.get('name', '')} "
            f"| {human_bool(v.get('enabled', True))} "
            f"| {human_bool(v.get('learn', False))} "
            f"| {human_bool(v.get('alarm', False))} "
            f"| {human_bool(v.get('block', False))} |"
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
table.findings{width:100%;border-collapse:collapse;margin:8px 0;font-size:.9em}
table.findings th{background:#1a1a2e;color:#fff;padding:8px 10px;text-align:left}
table.findings td{padding:7px 10px;border-bottom:1px solid #e0e0e0;vertical-align:top}
table.findings tr:nth-child(even){background:#f9f9f9}
table.findings tr:hover{background:#eef3ff}
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
        f"<tr><td>Baseline Policy</td><td>{_e(result.baseline_name)}</td></tr>",
        f"<tr><td>Audit Date</td><td>{_e(result.timestamp)}</td></tr>",
        f"<tr><td>Compliance Score</td><td><strong>{score:.1f}%</strong> {badge_pf}</td></tr>",
        "</table>",
        f"<div class='score-bar'><div class='{score_class} score-fill' style='width:{min(score,100):.1f}%'></div></div>",
        "</div>",
    ]

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

    # WAF Violations status table
    if result.violations:
        parts.append("<h2>WAF Violations Status</h2>")
        parts.append(_html_violations_table(result.violations))

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


def _html_violations_table(violations: List[dict]) -> str:
    rows = []
    for v in sorted(violations, key=lambda x: x.get("name", "")):
        def _badge(val: bool) -> str:
            cls = "pass" if val else "fail"
            label = "Enabled" if val else "Disabled"
            return f"<span class='badge badge-{cls}'>{label}</span>"

        rows.append(
            f"<tr>"
            f"<td>{_e(v.get('name', ''))}</td>"
            f"<td>{_badge(v.get('enabled', True))}</td>"
            f"<td>{_badge(v.get('learn', False))}</td>"
            f"<td>{_badge(v.get('alarm', False))}</td>"
            f"<td>{_badge(v.get('block', False))}</td>"
            f"</tr>"
        )
    return (
        "<table class='findings'>"
        "<thead><tr>"
        "<th>Violation</th><th>Enabled</th><th>Learn</th><th>Alarm</th><th>Block</th>"
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
        "| Policy | Partition | Enforcement | Score | Status | Critical | Warning | Info |",
        "|--------|-----------|-------------|-------|--------|----------|---------|------|",
    ]
    for r in results:
        status = "PASS" if r.score >= _PASS_THRESHOLD else "FAIL"
        totals = r.summary.get("totals", {})
        lines.append(
            f"| `{r.policy_path}` | {r.partition} | {r.enforcement_mode} "
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
        rows.append(
            f"<tr>"
            f"<td><code>{_e(r.policy_path)}</code></td>"
            f"<td>{_e(r.partition)}</td>"
            f"<td>{_e(r.enforcement_mode)}</td>"
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
        "<th>Score</th><th>Status</th><th>Critical</th><th>Warning</th><th>Info</th>"
        "</tr></thead><tbody>"
        + "".join(rows) +
        "</tbody></table></body></html>"
    )
    out = reports_dir / "summary_audit_report.html"
    out.write_text(content, encoding='utf-8')
    _log.info("Summary HTML: %s", out)
