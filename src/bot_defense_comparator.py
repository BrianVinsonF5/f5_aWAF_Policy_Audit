"""Bot Defense profile comparison engine.

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

# Override-related reference collections to compare and report.
# Tuples: (reference_key, inline_key, display_label)
_OVERRIDE_COLLECTIONS = [
    ("anomalyCategoryOverridesReference", "anomalyCategoryOverrides", "Anomaly Category Overrides"),
    ("anomalyOverridesReference", "anomalyOverrides", "Anomaly Overrides"),
    ("classOverridesReference", "classOverrides", "Class Overrides"),
    ("externalDomainsReference", "externalDomains", "External Domains"),
    ("microServicesReference", "microServices", "Micro Services"),
    ("signatureCategoryOverridesReference", "signatureCategoryOverrides", "Signature Category Overrides"),
    ("signatureOverridesReference", "signatureOverrides", "Signature Overrides"),
    ("siteDomainsReference", "siteDomains", "Site Domains"),
    ("stagedSignaturesReference", "stagedSignatures", "Staged Signatures"),
    ("whitelistReference", "whitelist", "Whitelist"),
]


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
    _cmp_bd_signature_enforcement(baseline, target, result)
    _cmp_bd_whitelist(baseline, target, result)
    _cmp_bd_browsers(baseline, target, result)
    _cmp_bd_overrides(baseline, target, result)

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

    # Store all tracked settings for the display table
    _all_tracked = (
        ["enforcementMode", "template", "browserMitigationAction"]
        + [a for a, _, _ in _enabled_disabled_attrs]
        + [a for a, _, _ in _info_attrs]
    )
    result.bot_mitigation_target   = {k: target.get(k)   for k in _all_tracked}
    result.bot_mitigation_baseline = {k: baseline.get(k) for k in _all_tracked}


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


def _get_subcollection(profile: Dict, key: str) -> List[Dict]:
    """
    Return the items list from a sub-collection field.

    Handles both expanded sub-collections (``{key}Reference: {items: [...]}``
    returned when the API is called with ``?expandSubcollections=true``) and
    inline lists (``{key}: [...]``).
    """
    # Expanded reference: signaturesReference.items / whitelistReference.items …
    ref = profile.get(f"{key}Reference", {})
    if isinstance(ref, dict) and "items" in ref:
        return ref["items"]
    # Inline list: signatures / whitelist / browsers
    inline = profile.get(key, [])
    if isinstance(inline, list):
        return inline
    return []


def _get_reference_subcollection(profile: Dict, ref_key: str, inline_key: str) -> List[Dict]:
    """Return items from a specific ``...Reference`` key with inline fallback."""
    ref = profile.get(ref_key, {})
    if isinstance(ref, dict) and isinstance(ref.get("items"), list):
        return ref.get("items", [])
    inline = profile.get(inline_key, [])
    if isinstance(inline, list):
        return inline
    return []


def _override_entry_key(entry: Dict) -> str:
    """Derive a stable display/comparison key for Bot Defense override entries."""
    for k in (
        "id", "name", "fullPath", "signatureId", "signatureName",
        "category", "className", "serviceName", "domain", "host",
        "ipAddress", "ip", "value",
    ):
        v = entry.get(k)
        if v not in (None, ""):
            return str(v)
    # Deterministic fallback for entries without an obvious identity field.
    try:
        import json
        return json.dumps(entry, sort_keys=True)
    except Exception:
        return str(entry)


def _cmp_bd_signature_enforcement(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    """
    Compare Bot Defense signature / signature-category enforcement settings.

    Each entry is keyed by ``name`` (signature category name).  The relevant
    attributes per entry are ``enabled`` and ``action`` (block/detect/alarm).
    """
    b_sigs = {
        s.get("name", ""): s
        for s in _get_subcollection(baseline, "signatures")
        if s.get("name")
    }
    t_sigs = {
        s.get("name", ""): s
        for s in _get_subcollection(target, "signatures")
        if s.get("name")
    }

    if not b_sigs and not t_sigs:
        return

    # Action severity ranking: higher = more restrictive
    _ACTION_RANK: Dict[str, int] = {
        "detect": 0,
        "alarm":  0,
        "log":    0,
        "block":  1,
    }

    all_names = sorted(set(b_sigs) | set(t_sigs))
    display_rows: List[Dict] = []

    for name in all_names:
        b_entry = b_sigs.get(name)
        t_entry = t_sigs.get(name)

        if b_entry is None:
            # Extra in target — informational
            display_rows.append({
                "name": name,
                "baseline_enabled": None,
                "target_enabled": t_entry.get("enabled"),
                "baseline_action": None,
                "target_action": t_entry.get("action"),
                "baseline_match": "extra",
            })
            _add(result, DiffItem(
                section="bot-defense.signatures",
                element_name=name,
                attribute="enabled",
                baseline_value=None,
                target_value=t_entry.get("enabled"),
                severity=SEVERITY_INFO,
                description=f"Signature category '{name}' is present in target but not in baseline.",
            ))
            continue

        if t_entry is None:
            # Missing from target
            display_rows.append({
                "name": name,
                "baseline_enabled": b_entry.get("enabled"),
                "target_enabled": None,
                "baseline_action": b_entry.get("action"),
                "target_action": None,
                "baseline_match": "missing",
            })
            _add(result, DiffItem(
                section="bot-defense.signatures",
                element_name=name,
                attribute="enabled",
                baseline_value=b_entry.get("enabled"),
                target_value=None,
                severity=SEVERITY_WARNING,
                description=f"Signature category '{name}' is present in baseline but missing from target.",
            ))
            continue

        # Both present — compare enabled and action
        b_enabled = b_entry.get("enabled")
        t_enabled = t_entry.get("enabled")
        b_action  = b_entry.get("action")
        t_action  = t_entry.get("action")

        match = True
        if b_enabled != t_enabled:
            match = False
            sev = (
                SEVERITY_CRITICAL
                if b_enabled is True and t_enabled is False
                else SEVERITY_WARNING
            )
            _add(result, DiffItem(
                section="bot-defense.signatures",
                element_name=name,
                attribute="enabled",
                baseline_value=b_enabled,
                target_value=t_enabled,
                severity=sev,
                description=(
                    f"Signature category '{name}' enabled state differs. "
                    f"Baseline: {b_enabled}, Target: {t_enabled}."
                    + (" Category will NOT be enforced." if sev == SEVERITY_CRITICAL else "")
                ),
            ))

        if b_action is not None and b_action != t_action:
            match = False
            b_rank = _ACTION_RANK.get(str(b_action).lower(), 0)
            t_rank = _ACTION_RANK.get(str(t_action).lower(), 0)
            sev = SEVERITY_CRITICAL if t_rank < b_rank else SEVERITY_WARNING
            _add(result, DiffItem(
                section="bot-defense.signatures",
                element_name=name,
                attribute="action",
                baseline_value=b_action,
                target_value=t_action,
                severity=sev,
                description=(
                    f"Signature category '{name}' action changed from '{b_action}' to '{t_action}'."
                    + (" Enforcement has been weakened." if sev == SEVERITY_CRITICAL else "")
                ),
            ))

        display_rows.append({
            "name": name,
            "baseline_enabled": b_enabled,
            "target_enabled": t_enabled,
            "baseline_action": b_action,
            "target_action": t_action,
            "baseline_match": "match" if match else "diff",
        })

    result.bot_signatures = display_rows


def _cmp_bd_whitelist(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    """
    Compare Bot Defense whitelist (allowed/trusted source) entries.

    Entries are keyed by name.  Differences in ``ipAddress``, ``ipMask``,
    ``matchType``, ``enabled``, and ``description`` are flagged.
    """
    def _entry_key(e: Dict) -> str:
        return e.get("name") or e.get("ipAddress", "")

    b_wl = {_entry_key(e): e for e in _get_subcollection(baseline, "whitelist") if _entry_key(e)}
    t_wl = {_entry_key(e): e for e in _get_subcollection(target, "whitelist") if _entry_key(e)}

    if not b_wl and not t_wl:
        return

    all_keys = sorted(set(b_wl) | set(t_wl))
    display_rows: List[Dict] = []

    _CMP_ATTRS = ["ipAddress", "ipMask", "matchType", "enabled", "description"]

    for key in all_keys:
        b_entry = b_wl.get(key)
        t_entry = t_wl.get(key)

        if b_entry is None:
            # New whitelist entry in target — potential security relaxation
            display_rows.append({
                "name": key,
                "baseline_entry": None,
                "target_entry": t_entry,
                "baseline_match": "extra",
            })
            _add(result, DiffItem(
                section="bot-defense.whitelist",
                element_name=key,
                attribute="present",
                baseline_value=False,
                target_value=True,
                severity=SEVERITY_WARNING,
                description=(
                    f"Whitelist entry '{key}' is in target but not in baseline. "
                    "A new trusted source exception has been added."
                ),
            ))
            continue

        if t_entry is None:
            # Entry removed from target
            display_rows.append({
                "name": key,
                "baseline_entry": b_entry,
                "target_entry": None,
                "baseline_match": "missing",
            })
            _add(result, DiffItem(
                section="bot-defense.whitelist",
                element_name=key,
                attribute="present",
                baseline_value=True,
                target_value=False,
                severity=SEVERITY_INFO,
                description=f"Whitelist entry '{key}' is in baseline but missing from target.",
            ))
            continue

        # Both present — compare attributes
        differs = False
        for attr in _CMP_ATTRS:
            b_val = b_entry.get(attr)
            t_val = t_entry.get(attr)
            if b_val is not None and b_val != t_val:
                differs = True
                sev = (
                    SEVERITY_CRITICAL
                    if attr == "enabled" and b_val is True and t_val is False
                    else SEVERITY_WARNING
                )
                _add(result, DiffItem(
                    section="bot-defense.whitelist",
                    element_name=key,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=f"Whitelist entry '{key}' attribute '{attr}' differs from baseline.",
                ))

        display_rows.append({
            "name": key,
            "baseline_entry": b_entry,
            "target_entry": t_entry,
            "baseline_match": "diff" if differs else "match",
        })

    result.bot_whitelist = display_rows


def _cmp_bd_browsers(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    """
    Compare Bot Defense browser validation settings.

    Entries are keyed by ``name``.  The primary attribute is ``enabled``;
    any additional per-browser attributes present in the baseline are also
    compared.
    """
    b_br = {
        e.get("name", ""): e
        for e in _get_subcollection(baseline, "browsers")
        if e.get("name")
    }
    t_br = {
        e.get("name", ""): e
        for e in _get_subcollection(target, "browsers")
        if e.get("name")
    }

    if not b_br and not t_br:
        return

    all_names = sorted(set(b_br) | set(t_br))
    display_rows: List[Dict] = []

    for name in all_names:
        b_entry = b_br.get(name)
        t_entry = t_br.get(name)

        if b_entry is None:
            display_rows.append({
                "name": name,
                "baseline_entry": None,
                "target_entry": t_entry,
                "baseline_match": "extra",
            })
            _add(result, DiffItem(
                section="bot-defense.browsers",
                element_name=name,
                attribute="present",
                baseline_value=False,
                target_value=True,
                severity=SEVERITY_INFO,
                description=f"Browser entry '{name}' is present in target but not in baseline.",
            ))
            continue

        if t_entry is None:
            display_rows.append({
                "name": name,
                "baseline_entry": b_entry,
                "target_entry": None,
                "baseline_match": "missing",
            })
            _add(result, DiffItem(
                section="bot-defense.browsers",
                element_name=name,
                attribute="present",
                baseline_value=True,
                target_value=False,
                severity=SEVERITY_WARNING,
                description=f"Browser entry '{name}' is in baseline but missing from target.",
            ))
            continue

        # Compare all attributes present in baseline entry
        differs = False
        for attr, b_val in b_entry.items():
            if attr in ("name", "kind", "selfLink", "generation", "lastUpdateMicros"):
                continue
            t_val = t_entry.get(attr)
            if b_val != t_val:
                differs = True
                sev = (
                    SEVERITY_CRITICAL
                    if attr == "enabled" and b_val is True and t_val is False
                    else SEVERITY_WARNING
                )
                _add(result, DiffItem(
                    section="bot-defense.browsers",
                    element_name=name,
                    attribute=attr,
                    baseline_value=b_val,
                    target_value=t_val,
                    severity=sev,
                    description=(
                        f"Browser '{name}' attribute '{attr}' differs from baseline."
                        + (" Browser validation disabled." if sev == SEVERITY_CRITICAL else "")
                    ),
                ))

        display_rows.append({
            "name": name,
            "baseline_entry": b_entry,
            "target_entry": t_entry,
            "baseline_match": "diff" if differs else "match",
        })

    result.bot_browsers = display_rows


def _cmp_bd_overrides(
    baseline: Dict, target: Dict, result: ComparisonResult
) -> None:
    """
    Compare override-oriented Bot Defense collections.

    The baseline profile is expected to contain no override entries. Any
    override entries found in target are recorded in ``result.bot_overrides``
    and flagged as WARNING differences.
    """
    display_rows: List[Dict] = []

    for ref_key, inline_key, label in _OVERRIDE_COLLECTIONS:
        b_items = _get_reference_subcollection(baseline, ref_key, inline_key)
        t_items = _get_reference_subcollection(target, ref_key, inline_key)

        b_map = {
            _override_entry_key(e): e
            for e in b_items if isinstance(e, dict)
        }
        t_map = {
            _override_entry_key(e): e
            for e in t_items if isinstance(e, dict)
        }

        all_keys = sorted(set(b_map) | set(t_map))
        for key in all_keys:
            b_entry = b_map.get(key)
            t_entry = t_map.get(key)

            if b_entry is None:
                display_rows.append({
                    "collection": label,
                    "name": key,
                    "baseline_entry": None,
                    "target_entry": t_entry,
                    "baseline_match": "extra",
                })
                _add(result, DiffItem(
                    section=f"bot-defense.overrides.{inline_key}",
                    element_name=key,
                    attribute="present",
                    baseline_value=False,
                    target_value=True,
                    severity=SEVERITY_WARNING,
                    description=(
                        f"Override entry '{key}' was added in '{label}' on target profile."
                    ),
                ))
                result.extra_in_target.append(
                    {"section": f"bot-defense.overrides.{inline_key}", "name": key}
                )
                continue

            if t_entry is None:
                display_rows.append({
                    "collection": label,
                    "name": key,
                    "baseline_entry": b_entry,
                    "target_entry": None,
                    "baseline_match": "missing",
                })
                _add(result, DiffItem(
                    section=f"bot-defense.overrides.{inline_key}",
                    element_name=key,
                    attribute="present",
                    baseline_value=True,
                    target_value=False,
                    severity=SEVERITY_INFO,
                    description=(
                        f"Override entry '{key}' from baseline '{label}' is missing on target."
                    ),
                ))
                result.missing_in_target.append(
                    {"section": f"bot-defense.overrides.{inline_key}", "name": key}
                )
                continue

            # Both present — detect content drift.
            if b_entry != t_entry:
                display_rows.append({
                    "collection": label,
                    "name": key,
                    "baseline_entry": b_entry,
                    "target_entry": t_entry,
                    "baseline_match": "diff",
                })
                _add(result, DiffItem(
                    section=f"bot-defense.overrides.{inline_key}",
                    element_name=key,
                    attribute="content",
                    baseline_value=b_entry,
                    target_value=t_entry,
                    severity=SEVERITY_WARNING,
                    description=(
                        f"Override entry '{key}' in '{label}' differs from baseline."
                    ),
                ))
            else:
                display_rows.append({
                    "collection": label,
                    "name": key,
                    "baseline_entry": b_entry,
                    "target_entry": t_entry,
                    "baseline_match": "match",
                })

    result.bot_overrides = display_rows
