# WAF Policy Compliance Report for `/Common/example` on `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

## Policy: `/Common/example`

- **Partition:** Common
- **Enforcement Mode:** transparent
- **Baseline Policy:** baseline.xml
- **Audit Date:** 2026-04-03T19:48:05Z
- **Compliance Score:** 100.0% — **PASS** (threshold: 90%)

### Virtual Server Bindings

*No virtual server bindings found for this policy.*

## Recent ASM Security Policy Changes

Last 10 policy audit-log entries from BIG-IP `/mgmt/tm/asm/policies/<id>/audit-logs`.

| # | Timestamp | User | Change |
|---:|-----------|------|--------|
| 1 | — | — | — |
| 2 | — | — | Internal Statistics have been updated |
| 3 | — | — | Active was set to true. |
| 4 | — | — | — |
| 5 | — | admin | Type was set to Security.
Encoding Selected was set to false.
Application Language was set to utf-8.
Case Sensitivity was set to Case Sensitive.
Learning Mode was set to Automatic.
Template was set to POLICY_TEMPLATE_PASSIVE.
Active was set to false.
Differentiate between HTTP and HTTPS URLs was set to Protocol Specific.
Policy Name was set to /Common/example.
Passive Mode was set to enabled.
Enforcement Mode was set to Transparent. |

## Attack Signature Sets

All Attack Signature Sets applied to this policy and their Learn / Alarm / Block status.

| Signature Set Name | Type | Learn | Alarm | Block | Baseline Match |
|--------------------|------|:-----:|:-----:|:-----:|:--------------:|
| Generic Detection Signatures (High/Medium Accuracy) | filter-based | Enabled | Enabled | Enabled | ✓ Match |

## Policy Builder Status

**Learning Mode:** `Automatic` — **✅ AUTOMATIC**

### Policy Builder Settings

| Section | Setting | Baseline | Target | Match |
|---------|---------|----------|--------|-------|
| Core | Learning Mode | Automatic | Automatic | ✓ |
| Core | Fully Automatic | Enabled | Enabled | ✓ |
| Core | Client-Side Policy Building | Disabled | Disabled | ✓ |
| Core | Learn From Responses | Disabled | Disabled | ✓ |
| Core | Learn Inactive Entities | Enabled | Enabled | ✓ |
| Core | Enable Full Policy Inspection | Enabled | Enabled | ✓ |
| Core | Auto Apply Frequency | real-time | real-time | ✓ |
| Core | Auto Apply Start Time | 00:00 | 00:00 | ✓ |
| Core | Auto Apply End Time | 23:59 | 23:59 | ✓ |
| Core | Apply on All Days | Enabled | Enabled | ✓ |
| Core | Apply at All Times | Enabled | Enabled | ✓ |
| Core | Learn Only from Non-Bot Traffic | Enabled | Enabled | ✓ |
| Core | All Trusted IPs Source | list | list | ✓ |
| Core | Response Codes | 1xx, 2xx, 3xx | 1xx, 2xx, 3xx | ✓ |
| Cookie | Learn Cookies | When Violation Detected | When Violation Detected | ✓ |
| Cookie | Max Modified Cookies | 100 | 100 | ✓ |
| Cookie | Collapse Cookies | Disabled | Disabled | ✓ |
| Cookie | Enforce Unmodified Cookies | Disabled | Disabled | ✓ |
| File Type | Learn File Types | Compact | Compact | ✓ |
| File Type | Maximum File Types | 50 | 50 | ✓ |
| Parameter | Learn Parameters | Compact | Compact | ✓ |
| Parameter | Maximum Parameters | 100 | 100 | ✓ |
| Parameter | Parameter Level | global | global | ✓ |
| Parameter | Collapse Parameters | Enabled | Enabled | ✓ |
| Parameter | Classify Parameters | Enabled | Enabled | ✓ |
| URL | Learn URLs | Compact | Compact | ✓ |
| URL | Learn WebSocket URLs | Always | Always | ✓ |
| URL | Maximum URLs | 100 | 100 | ✓ |
| URL | Collapse URLs | Disabled | Disabled | ✓ |
| URL | Classify URLs | Enabled | Enabled | ✓ |
| Header | Valid Host Names | Enabled | Enabled | ✓ |
| Header | Maximum Hosts | 10000 | 10000 | ✓ |
| Redirection Protection | Learn Redirection Domains | Always | Always | ✓ |
| Redirection Protection | Max Redirection Domains | 100 | 100 | ✓ |
| Sessions & Logins | Learn Login Pages | Disabled | Disabled | ✓ |
| Server Technologies | Learn Server Technologies | Enabled | Enabled | ✓ |
| Central Configuration | Building Mode | local | local | ✓ |
| Central Configuration | Event Correlation Mode | local | local | ✓ |

## WAF Violations Status

| ID | Violation Name | Alarm | Block | Learn | PB Tracking | Matches Baseline | Baseline (A/B/L) |
|----|----------------|:-----:|:-----:|:-----:|:-----------:|:----------------:|:----------------:|
| `BRUTE_FORCE_ATTACK_DETECTED` | Brute Force: Maximum login attempts are exceeded | Enabled | Enabled | Disabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Disabled |
| `COOKIE_LEN` | Illegal cookie length | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `CSRF` | CSRF attack detected | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `CSRF_EXPIRED` | CSRF authentication expired | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `EMPTY_PARAM_VALUE` | Illegal empty parameter value | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `HEADER_LEN` | Illegal header length | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `HEADER_REPEATED` | Illegal repeated header | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `ILLEGAL_INGRESS_OBJECT` | Login URL bypassed | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `ILLEGAL_METHOD` | Illegal method | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `METACHAR_IN_HEADER` | Illegal meta character in header | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `MISSING_MANDATORY_HEADER` | Mandatory HTTP header is missing | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `MOD_ASM_COOKIE` | Modified ASM cookie | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `MOD_DOMAIN_COOKIE` | Modified domain cookie(s) | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `NUM_OF_MANDATORY_PARAMS` | Illegal number of mandatory parameters | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `PARAM_NUMERIC_VALUE` | Illegal parameter numeric value | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `PARAM_VALUE_NOT_MATCHING_REGEX` | Parameter value does not comply with regular expression | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `PARSER_EXPIRED_INGRESS_OBJECT` | Login URL expired | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `REPEATED_PARAMETER_NAME` | Illegal repeated parameter name | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `REQUEST_TOO_LONG` | Request length exceeds defined buffer size | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `STATIC_PARAM_VALUE` | Illegal static parameter value | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `VIRUS_DETECTED` | Virus detected | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `WEBSOCKET_BAD_REQUEST` | Bad WebSocket handshake request | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED` | Binary content found in text only WebSocket | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `WEBSOCKET_FRAME_MASKING` | Mask not found in client frame | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_FRAMING_PROTOCOL` | Failure in WebSocket framing protocol | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED` | Text content found in binary only WebSocket | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |

## Executive Summary

| Category | Critical | Warning | Info | Total |
|----------|----------|---------|------|-------|
| **Totals** | **0** | **0** | **0** | **0** |

- **Missing elements (in baseline, absent in target):** 0
- **Extra elements (in target, not in baseline):** 0

## Blocking Section — Violations Comparison

Compares each violation's Alarm / Block / Learn flags against the baseline.
Cells marked with ⚠ differ from baseline; 🚨 indicates a critical security gap.

| ID | Violation Name | Attr | Baseline | Target | Severity |
|----|----------------|------|:--------:|:------:|----------|
| — | *(no differences detected)* | — | — | — | — |
