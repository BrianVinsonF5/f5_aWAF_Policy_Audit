"""
Bot Defense profile comparison engine.

Compares a target Bot Defense profile (fetched from the BIG-IP REST API
at /mgmt/tm/security/bot-defense/profile) against a baseline profile dict
and produces a ComparisonResult with severity-annotated DiffItem entries
and a compliance score.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .policy_comparator import (
    ComparisonResult, DiffItem,
    SEVERITY_CRITICAL, SEVERITY_WARNING, SEVERITY_INFO,
    _add, _calculate_score, _build_summary,
)
from .utils import get_logger, iso_timestamp

_log = get_logger("bot_defense_comparator")

# Template security ranking: higher = more secure
_TEMPLATE_RANK: Dict[str, int] = {
    "relaxed":  0,
    "balanced": 1,
    "strict":   2,
}


# ── Main entry point ───────────────────────────────────────────────────────────

def compare_bot_profiles(
    baseline: Dict,
    target: Dict,
    profile_meta: Optional[Dict] = None,
    baseline_name: str = "baseline",
    device_hostname: str = "",
    device_mgmt_ip: str = "",
    virtual_servers: Optional[List[Dict]] = None,
) -> ComparisonResult:
    """
    Compare a target Bot Defense profile dict against a baseline dict.

    Both dicts should be the raw JSON from the BIG-IP REST API:
      GET /mgmt/tm/security/bot-defense/profile/{name}

    profile_meta may contain 'name', 'fullPath', and 'partition' keys.
    virtual_servers is the list produced by
    BotDefenseAuditor.enrich_with_virtual_servers() — the Virtual Servers
    to which this profile is applied (directly or via Local Traffic Policy).
    Returns a ComparisonResult with profile_type="bot" set.
    """
    meta = profile_meta or {}
    full_path = meta.get("fullPath") or target.get("fullPath", "unknown")
    partition = (
        full_path.strip("/").split("/")[0]
        if full_path and full_path != "unknown"
        else "Common"
    )
    name = meta.get("name") or target.get("name", "unknown")

    result = ComparisonResult(
        policy_name=name,
        policy_path=full_path,
        partition=partition,
        enforcement_mode=target.get("enforcementMode", "transparent"),
        baseline_name=baseline_name,
        timestamp=iso_timestamp(),
        virtual_servers=virtual_servers or [],
        device_hostname=device_hostname,
        device_mgmt_ip=device_mgmt_ip,
        profile_type="bot",
    )

    _cmp_bd_core(baseline, target, result)
    _cmp_bd_mobile_detection(baseline, target, result)

    _build_summary(result)
    result.score = _calculate_score(result.diffs)
    return result


# ── Section comparators ────────────────────────────────────────────────────────

def _cmp_bd_core(baseline: Dict, target: Dict, result: ComparisonResult) -> None:
    """Compare top-level Bot Defense profile settings."""

    # enforcementMode: blocking vs transparent → CRITICAL if downgraded
    b_mode = baseline.get("enforcementMode", "transparent")
    t_mode = target.get("enforcementMode", "transparent")
    if b_mode != t_mode:
        sev = (
            SEVERITY_CRITICAL
            if b_mode == "blocking" and t_mode != "blocking"
            else SEVERITY_WARNING
        )
        _add(result, DiffItem(
            section="bot-defense",
            element_name="enforcementMode",
            attribute="enforcementMode",
            baseline_value=b_mode,
            target_value=t_mode,
            severity=sev,
            description=(
                f"Bot Defense enforcement mode differs. Baseline: '{b_mode}', Target: '{t_mode}'."
                + (" Bot threats will NOT be blocked." if sev == SEVERITY_CRITICAL else "")
            ),
        ))

    # template: strict/balanced/relaxed — downgrade is CRITICAL, upgrade/lateral WARNING
    b_tmpl = baseline.get("template")
    t_tmpl = target.get("template")
    if b_tmpl is not None and b_tmpl != t_tmpl:
        b_rank = _TEMPLATE_RANK.get(str(b_tmpl), 1)
        t_rank = _TEMPLATE_RANK.get(str(t_tmpl), 1)
        sev = SEVERITY_CRITICAL if t_rank < b_rank else SEVERITY_WARNING
        _add(result, DiffItem(
            section="bot-defense",
            element_name="template",
            attribute="template",
            baseline_value=b_tmpl,
            target_value=t_tmpl,
            severity=sev,
            description=(
                f"Bot Defense template changed from '{b_tmpl}' to '{t_tmpl}'."
                + (" Security posture has been weakened." if sev == SEVERITY_CRITICAL else "")
            ),
        ))

    # browserMitigationAction: block → non-block is CRITICAL
    b_bma = baseline.get("browserMitigationAction")
    t_bma = target.get("browserMitigationAction")
    if b_bma is not None and b_bma != t_bma:
        sev = (
            SEVERITY_CRITICAL
            if b_bma == "block" and t_bma != "block"
            else SEVERITY_WARNING
        )
        _add(result, DiffItem(
            section="bot-defense",
            element_name="browserMitigationAction",
            attribute="browserMitigationAction",
            baseline_value=b_bma,
            target_value=t_bma,
            severity=sev,
            description=(
                f"Browser mitigation action changed from '{b_bma}' to '{t_bma}'."
                + (" Suspicious browsers will NOT be blocked." if sev == SEVERITY_CRITICAL else "")
            ),
        ))

    # Settings where baseline=enabled and target=disabled is a security downgrade (WARNING)
    _enabled_disabled_attrs = [
        ("allowBrowserAccess",
         SEVERITY_WARNING,
         "Allow browser access setting differs from baseline."),
        ("apiAccessStrictMitigation",
         SEVERITY_WARNING,
         "API access strict mitigation differs from baseline."),
        ("dosAttackStrictMitigation",
         SEVERITY_WARNING,
         "DoS attack strict mitigation differs from baseline."),
        ("signatureStagingUponUpdate",
         SEVERITY_WARNING,
         "Signature staging upon update setting differs from baseline."),
        ("crossDomainRequests",
         SEVERITY_WARNING,
         "Cross-domain requests setting differs from baseline."),
    ]
    for attr, sev, desc in _enabled_disabled_attrs:
        b_val = baseline.get(attr)
        t_val = target.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="bot-defense",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))

    # Informational settings
    _info_attrs = [
        ("performChallengeInTransparent",
         SEVERITY_INFO,
         "Perform challenge in transparent mode differs from baseline."),
        ("singlePageApplication",
         SEVERITY_INFO,
         "Single page application setting differs from baseline."),
        ("deviceidMode",
         SEVERITY_INFO,
         "Device ID mode differs from baseline."),
        ("gracePeriod",
         SEVERITY_INFO,
         "Grace period differs from baseline."),
        ("enforcementReadinessPeriod",
         SEVERITY_INFO,
         "Enforcement readiness period differs from baseline."),
    ]
    for attr, sev, desc in _info_attrs:
        b_val = baseline.get(attr)
        t_val = target.get(attr)
        if b_val is not None and b_val != t_val:
            _add(result, DiffItem(
                section="bot-defense",
                element_name=attr,
                attribute=attr,
                baseline_value=b_val,
                target_value=t_val,
                severity=sev,
                description=desc,
            ))


def _cmp_bd_mobile_detection(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    """Compare the mobileDetection sub-object."""
    b_md = baseline.get("mobileDetection", {})
    t_md = target.get("mobileDetection", {})
    if not b_md:
        return

    # Each tuple: (attr, baseline_secure_val, downgrade_desc, downgrade_sev, other_sev)
    # baseline_secure_val: the value in baseline that means "secure" — if target changes
    #   away from it, that is a potential security downgrade.
    # Set baseline_secure_val=None to skip directional severity logic.
    _md_checks = [
        (
            "allowAndroidRootedDevice",
            "disabled",
            "Rooted Android devices are blocked in baseline but ALLOWED in target.",
            SEVERITY_CRITICAL,
            SEVERITY_WARNING,
        ),
        (
            "allowEmulators",
            "disabled",
            "Emulators are blocked in baseline but ALLOWED in target.",
            SEVERITY_CRITICAL,
            SEVERITY_WARNING,
        ),
        (
            "allowJailbrokenDevices",
            "disabled",
            "Jailbroken iOS devices are blocked in baseline but ALLOWED in target.",
            SEVERITY_CRITICAL,
            SEVERITY_WARNING,
        ),
        (
            "blockDebuggerEnabledDevice",
            "enabled",
            "Debugger-enabled devices are blocked in baseline but NOT blocked in target.",
            SEVERITY_CRITICAL,
            SEVERITY_WARNING,
        ),
        (
            "allowAnyAndroidPackage",
            None,
            "",
            SEVERITY_WARNING,
            SEVERITY_WARNING,
        ),
        (
            "allowAnyIosPackage",
            None,
            "",
            SEVERITY_WARNING,
            SEVERITY_WARNING,
        ),
        (
            "clientSideChallengeMode",
            None,
            "",
            SEVERITY_WARNING,
            SEVERITY_WARNING,
        ),
    ]

    for attr, secure_val, downgrade_desc, downgrade_sev, other_sev in _md_checks:
        b_val = b_md.get(attr)
        t_val = t_md.get(attr)
        if b_val is None or b_val == t_val:
            continue

        # Determine severity: if this is a known security downgrade, use downgrade_sev
        if secure_val and b_val == secure_val:
            sev = downgrade_sev
            desc = downgrade_desc
        else:
            sev = other_sev
            desc = f"Mobile detection '{attr}' differs from baseline. Baseline: '{b_val}', Target: '{t_val}'."

        _add(result, DiffItem(
            section="bot-defense.mobileDetection",
            element_name=attr,
            attribute=attr,
            baseline_value=b_val,
            target_value=t_val,
            severity=sev,
            description=desc,
        ))
