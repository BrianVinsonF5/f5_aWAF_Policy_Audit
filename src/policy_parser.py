"""
XML ASM/AWAF policy parser and normalizer.

Converts an F5 BIG-IP ASM XML export into a normalized Python dictionary
suitable for comparison.  Handles both namespaced and non-namespaced XML.
"""
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from lxml import etree as ET
    _LXML = True
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore
    _LXML = False

from .utils import get_logger

_log = get_logger("policy_parser")


# ── Namespace helpers ──────────────────────────────────────────────────────────

def _strip_ns(tag: str) -> str:
    """Remove XML namespace from a tag, e.g. '{http://...}name' → 'name'."""
    return re.sub(r'\{[^}]+\}', '', tag)


def _find(element, tag: str):
    """Find a child element ignoring XML namespaces."""
    # Direct match first
    child = element.find(tag)
    if child is not None:
        return child
    # Namespace-agnostic search
    for child in element:
        if _strip_ns(child.tag) == tag:
            return child
    return None


def _findall(element, tag: str) -> List:
    """Find all children with a given tag, ignoring XML namespaces."""
    results = element.findall(tag)
    if results:
        return results
    return [c for c in element if _strip_ns(c.tag) == tag]


def _text(element, tag: str, default: str = "") -> str:
    child = _find(element, tag)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes", "enabled")


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _norm_bool(element, tag: str, default: bool = False) -> bool:
    child = _find(element, tag)
    if child is not None and child.text:
        return _bool(child.text)
    return default


def _item_as_bool(el, attr: str) -> bool:
    val = el.get(attr, "") or _text(el, attr)
    return _bool(val)


# ── Top-level parsers ──────────────────────────────────────────────────────────

def _parse_general(root) -> Dict:
    gen = _find(root, "general")
    if gen is None:
        return {}
    return {
        "enforcementMode":          _text(gen, "enforcement-mode", "transparent"),
        "signatureStaging":         _norm_bool(gen, "signature-staging"),
        "placeholderSignatures":    _norm_bool(gen, "placeholder-signatures"),
        "responseLogging":          _text(gen, "response-logging", "none"),
        "trustXff":                 _norm_bool(gen, "trust-xff"),
        "allowedResponseCodes":     [
            _int(c.text)
            for c in _findall(gen, "allowed-response-code")
            if c.text
        ],
        "maskCreditCardNumbers":    _norm_bool(gen, "mask-credit-card-numbers"),
        "customXffHeaders":         [
            c.text.strip()
            for c in _findall(gen, "custom-xff-header")
            if c.text
        ],
        "enforcementReadinessPeriod": _int(_text(gen, "enforcement-readiness-period"), 7),
    }


def _parse_blocking_item(el) -> Dict:
    # enabled: check XML attribute first, then child element; default True if absent
    enabled_raw = el.get("enabled") or _text(el, "enabled")
    return {
        "name":    el.get("name") or _text(el, "name"),
        "enabled": _bool(enabled_raw) if enabled_raw else True,
        "alarm":   _item_as_bool(el, "alarm"),
        "block":   _item_as_bool(el, "block"),
        "learn":   _item_as_bool(el, "learn"),
    }


def _parse_blocking_settings(root) -> Dict:
    bs = _find(root, "blocking-settings")
    if bs is None:
        return {"violations": [], "evasions": [], "http-protocols": []}
    return {
        "violations":      [_parse_blocking_item(v) for v in _findall(bs, "violation")],
        "evasions":        [_parse_blocking_item(e) for e in _findall(bs, "evasion")],
        "http-protocols":  [_parse_blocking_item(h) for h in _findall(bs, "http-protocol")],
    }


def _parse_attack_signatures(root) -> List[Dict]:
    sigs_el = _find(root, "attack-signatures")
    if sigs_el is None:
        return []
    results = []
    for sig in _findall(sigs_el, "signature"):
        results.append({
            "signatureId":    _int(_text(sig, "signature-id") or sig.get("signature-id", "0")),
            "enabled":        _norm_bool(sig, "enabled", True),
            "performStaging": _norm_bool(sig, "perform-staging"),
            "inPolicy":       _norm_bool(sig, "in-policy", True),
        })
    return results


def _parse_signature_sets(root) -> List[Dict]:
    sets_el = _find(root, "signature-sets")
    if sets_el is None:
        return []
    results = []
    for ss in _findall(sets_el, "signature-set"):
        results.append({
            "name":             _text(ss, "name") or ss.get("name", ""),
            "alarm":            _norm_bool(ss, "alarm"),
            "block":            _norm_bool(ss, "block"),
            "learn":            _norm_bool(ss, "learn"),
            "signatureSetType": _text(ss, "type", "filter-based"),
        })
    return results


def _parse_urls(root) -> List[Dict]:
    urls_el = _find(root, "urls")
    if urls_el is None:
        return []
    results = []
    for url in _findall(urls_el, "url"):
        method_overrides = []
        mo_el = _find(url, "method-overrides")
        if mo_el is not None:
            for mo in _findall(mo_el, "method-override"):
                method_overrides.append({
                    "method":  _text(mo, "method"),
                    "allowed": _norm_bool(mo, "allowed"),
                })
        results.append({
            "name":                  _text(url, "name") or url.get("name", ""),
            "protocol":              _text(url, "protocol", "http"),
            "type":                  _text(url, "type", "explicit"),
            "isAllowed":             _norm_bool(url, "is-allowed", True),
            "attackSignaturesCheck": _norm_bool(url, "attack-signatures-check", True),
            "metacharsOnUrlCheck":   _norm_bool(url, "metachars-on-url-check", True),
            "methodOverrides":       method_overrides,
        })
    return results


def _parse_filetypes(root) -> List[Dict]:
    ft_el = _find(root, "filetypes")
    if ft_el is None:
        return []
    results = []
    for ft in _findall(ft_el, "filetype"):
        results.append({
            "name":           _text(ft, "name") or ft.get("name", ""),
            "allowed":        _norm_bool(ft, "allowed", True),
            "responseCheck":  _norm_bool(ft, "response-check"),
            "type":           _text(ft, "type", "explicit"),
        })
    return results


def _parse_parameters(root) -> List[Dict]:
    params_el = _find(root, "parameters")
    if params_el is None:
        return []
    results = []
    for param in _findall(params_el, "parameter"):
        results.append({
            "name":                  _text(param, "name") or param.get("name", ""),
            "type":                  _text(param, "type", "explicit"),
            "level":                 _text(param, "level", "global"),
            "parameterLocation":     _text(param, "parameter-location", "query"),
            "valueType":             _text(param, "value-type", "user-input"),
            "allowEmptyValue":       _norm_bool(param, "allow-empty-value"),
            "checkAttackSignatures": _norm_bool(param, "attack-signatures-check", True),
            "checkMetachars":        _norm_bool(param, "check-metachars", True),
            "sensitiveParameter":    _norm_bool(param, "sensitive"),
        })
    return results


def _parse_headers(root) -> List[Dict]:
    hdrs_el = _find(root, "headers")
    if hdrs_el is None:
        return []
    results = []
    for hdr in _findall(hdrs_el, "header"):
        results.append({
            "name":            _text(hdr, "name") or hdr.get("name", ""),
            "type":            _text(hdr, "type", "explicit"),
            "mandatory":       _norm_bool(hdr, "mandatory"),
            "checkSignatures": _norm_bool(hdr, "check-signatures", True),
        })
    return results


def _parse_cookies(root) -> List[Dict]:
    cookies_el = _find(root, "cookies")
    if cookies_el is None:
        return []
    results = []
    for ck in _findall(cookies_el, "cookie"):
        results.append({
            "name":                  _text(ck, "name") or ck.get("name", ""),
            "type":                  _text(ck, "type", "explicit"),
            "enforcementType":       _text(ck, "enforcement-type", "allow"),
            "insertSameSiteAttribute": _text(ck, "insert-same-site-attribute", "none"),
            "decodeValueAsBase64":   _text(ck, "decode-value-as-base64", "disabled"),
        })
    return results


def _parse_methods(root) -> List[Dict]:
    methods_el = _find(root, "methods")
    if methods_el is None:
        return []
    results = []
    for m in _findall(methods_el, "method"):
        results.append({
            "name":        _text(m, "name") or m.get("name", ""),
            "actAsMethod": _text(m, "act-as-method", ""),
        })
    return results


def _parse_http_protocols(root) -> List[Dict]:
    hp_el = _find(root, "http-protocols")
    if hp_el is None:
        return []
    results = []
    for hp in _findall(hp_el, "http-protocol"):
        results.append({
            "description": _text(hp, "description") or hp.get("description", ""),
            "enabled":     _norm_bool(hp, "enabled", True),
            "maxHeaders":  _int(_text(hp, "max-headers"), 0),
            "maxParams":   _int(_text(hp, "max-params"), 0),
        })
    return results


def _parse_evasions(root) -> List[Dict]:
    evasions_el = _find(root, "evasions")
    if evasions_el is None:
        return []
    results = []
    for ev in _findall(evasions_el, "evasion"):
        results.append({
            "description": _text(ev, "description") or ev.get("description", ""),
            "enabled":     _norm_bool(ev, "enabled", True),
        })
    return results


def _parse_data_guard(root) -> Dict:
    dg = _find(root, "data-guard")
    if dg is None:
        return {"enabled": False}
    patterns = [
        p.text.strip() for p in _findall(dg, "custom-pattern") if p.text
    ]
    enforcement_urls = [
        u.text.strip() for u in _findall(dg, "enforcement-url") if u.text
    ]
    return {
        "enabled":               _norm_bool(dg, "enabled"),
        "creditCardNumbers":     _norm_bool(dg, "credit-card-numbers"),
        "socialSecurityNumbers": _norm_bool(dg, "us-social-security-numbers"),
        "customPatterns":        patterns,
        "enforcementMode":       _text(dg, "enforcement-mode", "ignore-urls-in-list"),
        "enforcementUrls":       enforcement_urls,
    }


def _parse_brute_force(root) -> List[Dict]:
    bf_el = _find(root, "brute-force-attack-preventions")
    if bf_el is None:
        return []
    results = []
    for entry in _findall(bf_el, "brute-force-attack-prevention"):
        settings = {}
        settings_el = _find(entry, "brute-force-protection-settings")
        if settings_el is not None:
            for child in settings_el:
                settings[_strip_ns(child.tag)] = child.text.strip() if child.text else ""
        results.append({
            "urlName":          _text(entry, "url-name"),
            "maxLoginAttempts": _int(_text(entry, "max-login-attempts"), 0),
            "settings":         settings,
        })
    return results


def _parse_ip_intelligence(root) -> Dict:
    ip_el = _find(root, "ip-intelligence")
    if ip_el is None:
        return {"enabled": False, "categories": []}
    categories = []
    cats_el = _find(ip_el, "ip-intelligence-categories")
    if cats_el is not None:
        for cat in _findall(cats_el, "ip-intelligence-category"):
            categories.append({
                "name":  _text(cat, "category"),
                "alarm": _norm_bool(cat, "alarm"),
                "block": _norm_bool(cat, "block"),
            })
    return {
        "enabled":    _norm_bool(ip_el, "enabled"),
        "categories": categories,
    }


def _parse_bot_defense(root) -> Dict:
    bd = _find(root, "bot-defense")
    if bd is None:
        return {"enabled": False}
    result: Dict[str, Any] = {"enabled": _norm_bool(bd, "enabled")}
    ms_el = _find(bd, "mitigation-settings")
    if ms_el is not None:
        result["mitigationSettings"] = {
            _strip_ns(c.tag): c.text.strip() if c.text else ""
            for c in ms_el
        }
    bv_el = _find(bd, "browser-verification")
    if bv_el is not None:
        result["browserVerification"] = bv_el.text.strip() if bv_el.text else ""
    return result


def _parse_login_pages(root) -> List[Dict]:
    lp_el = _find(root, "login-pages")
    if lp_el is None:
        return []
    results = []
    for lp in _findall(lp_el, "login-page"):
        settings = {
            _strip_ns(c.tag): c.text.strip() if c.text else ""
            for c in lp
            if _strip_ns(c.tag) not in ("url", "authentication-type")
        }
        results.append({
            "url":                _text(lp, "url"),
            "authenticationType": _text(lp, "authentication-type", "none"),
            "settings":           settings,
        })
    return results


def _parse_policy_builder(root) -> Dict:
    pb = _find(root, "policy-builder")
    if pb is None:
        return {}
    result: Dict[str, Any] = {
        "learningMode":       _text(pb, "learning-mode", "disabled"),
    }
    rsc_el = _find(pb, "response-status-codes")
    if rsc_el is not None:
        result["responseStatusCodes"] = [
            _int(c.text) for c in _findall(rsc_el, "response-status-code") if c.text
        ]
    return result


def _parse_whitelist_ips(root) -> List[Dict]:
    wl_el = _find(root, "whitelist-ips")
    if wl_el is None:
        return []
    results = []
    for ip_el in _findall(wl_el, "whitelist-ip"):
        results.append({
            "ipAddress":            _text(ip_el, "ip-address") or ip_el.get("ip-address", ""),
            "ipMask":               _text(ip_el, "ip-mask") or ip_el.get("ip-mask", "255.255.255.255"),
            "trustedByPolicyBuilder": _norm_bool(ip_el, "trusted-by-policy-builder"),
            "ignoreAnomalies":      _norm_bool(ip_el, "ignore-anomalies"),
            "ignoreIpReputation":   _norm_bool(ip_el, "ignore-ip-reputation"),
        })
    return results


# ── Public API ─────────────────────────────────────────────────────────────────

def get_policy_metadata(xml_path: str) -> Dict:
    """Extract high-level metadata from the policy XML header."""
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {xml_path}")

    tree = _parse_tree(xml_path)
    root = tree.getroot()
    # Strip namespace from root tag if present
    if _strip_ns(root.tag) != "policy":
        # Some exports wrap in a <policies> element
        for child in root:
            if _strip_ns(child.tag) == "policy":
                root = child
                break

    return {
        "name":        _text(root, "name") or root.get("name", ""),
        "fullPath":    _text(root, "full-path") or root.get("fullPath", ""),
        "description": _text(root, "description"),
        "version":     root.get("version", ""),
        "createdAt":   _text(root, "created-at"),
        "updatedAt":   _text(root, "updated-at"),
    }


def parse_policy(xml_path: str) -> Dict:
    """
    Parse an F5 ASM XML policy export into a normalized Python dict.

    Returns a nested dictionary with keys matching each policy section.
    """
    _log.debug("Parsing policy XML: %s", xml_path)
    tree = _parse_tree(xml_path)
    root = tree.getroot()

    # Handle wrapping <policies> element
    if _strip_ns(root.tag) != "policy":
        for child in root:
            if _strip_ns(child.tag) == "policy":
                root = child
                break

    return {
        "general":             _parse_general(root),
        "blocking-settings":   _parse_blocking_settings(root),
        "attack-signatures":   _parse_attack_signatures(root),
        "signature-sets":      _parse_signature_sets(root),
        "urls":                _parse_urls(root),
        "filetypes":           _parse_filetypes(root),
        "parameters":          _parse_parameters(root),
        "headers":             _parse_headers(root),
        "cookies":             _parse_cookies(root),
        "methods":             _parse_methods(root),
        "http-protocols":      _parse_http_protocols(root),
        "evasions":            _parse_evasions(root),
        "data-guard":          _parse_data_guard(root),
        "brute-force":         _parse_brute_force(root),
        "ip-intelligence":     _parse_ip_intelligence(root),
        "bot-defense":         _parse_bot_defense(root),
        "login-pages":         _parse_login_pages(root),
        "policy-builder":      _parse_policy_builder(root),
        "whitelist-ips":       _parse_whitelist_ips(root),
    }


def _parse_tree(xml_path: str):
    """Parse XML file, handling encoding declarations robustly."""
    path = Path(xml_path)
    if _LXML:
        parser = ET.XMLParser(recover=True, encoding="utf-8")
        try:
            return ET.parse(str(path), parser)
        except Exception:
            # Try without encoding hint
            return ET.parse(str(path))
    else:
        return ET.parse(str(path))
