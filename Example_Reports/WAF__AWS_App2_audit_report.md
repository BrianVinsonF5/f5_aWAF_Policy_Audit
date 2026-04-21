# WAF Policy Compliance Report for `/AWS/App2` on `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

## Policy: `/AWS/App2`

- **Partition:** AWS
- **Enforcement Mode:** transparent
- **Baseline Policy:** baseline.xml
- **Audit Date:** 2026-04-03T19:48:05Z
- **Compliance Score:** 80.5% — **FAIL** (threshold: 90%)

### Virtual Server Bindings

| Virtual Server | IP Address | Port | Association | Local Traffic Policies |
|----------------|:----------:|:----:|:-----------:|------------------------|
| `/AWS/app1andapp2` | 20.20.20.2 | 80 | manual | `/AWS/AWS_ASM_Apply` |

## Recent ASM Security Policy Changes

Last 10 policy audit-log entries from BIG-IP `/mgmt/tm/asm/policies/<id>/audit-logs`.

| # | Timestamp | User | Change |
|---:|-----------|------|--------|
| 1 | — | admin | — |
| 2 | — | admin | Server Technology was set to MySQL. |
| 3 | — | admin | Policy Signature Set Name was set to MySQL Signatures (High/Medium Accuracy).
Learn was set to enabled.
Alarm was set to enabled.
Block was set to enabled. |
| 4 | — | admin | Server Technology was set to Backbone.js. |
| 5 | — | admin | Server Technology was set to AngularJS. |
| 6 | — | admin | Policy Signature Set Name was set to JavaScript Signatures (High/Medium Accuracy).
Learn was set to enabled.
Alarm was set to enabled.
Block was set to enabled. |
| 7 | — | admin | Dynamic Session ID in URL was set to (/sap([^)]+)). |
| 8 | — | — | — |
| 9 | — | — | Internal Statistics have been updated |
| 10 | — | — | Active was set to true. |

## Attack Signature Sets

All Attack Signature Sets applied to this policy and their Learn / Alarm / Block status.

| Signature Set Name | Type | Learn | Alarm | Block | Baseline Match |
|--------------------|------|:-----:|:-----:|:-----:|:--------------:|
| Generic Detection Signatures (High/Medium Accuracy) | filter-based | Enabled | Enabled | Enabled | ✓ Match |
| JavaScript Signatures (High/Medium Accuracy) | filter-based | Enabled | Enabled | Enabled | — N/A |
| MySQL Signatures (High/Medium Accuracy) | filter-based | Enabled | Enabled | Enabled | — N/A |

## Policy Builder Status

**Learning Mode:** `Automatic` — **✅ AUTOMATIC**

### Policy Builder Settings

| Section | Setting | Baseline | Target | Match |
|---------|---------|----------|--------|-------|
| Core | Learning Mode | Automatic | Automatic | ✓ |
| Core | Fully Automatic | Enabled | Enabled | ✓ |
| Core | Client-Side Policy Building | Disabled | Disabled | ✓ |
| Core | Learn From Responses | Disabled | Enabled | ⚠ |
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
| Cookie | Enforce Unmodified Cookies | Disabled | Enabled | ⚠ |
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
| Sessions & Logins | Learn Login Pages | Disabled | Enabled | ⚠ |
| Server Technologies | Learn Server Technologies | Enabled | Enabled | ✓ |
| Central Configuration | Building Mode | local | local | ✓ |
| Central Configuration | Event Correlation Mode | local | local | ✓ |

## WAF Violations Status

| ID | Violation Name | Alarm | Block | Learn | PB Tracking | Matches Baseline | Baseline (A/B/L) |
|----|----------------|:-----:|:-----:|:-----:|:-----------:|:----------------:|:----------------:|
| `ACCESS_INVALID` | Access token does not comply with the profile requirements | Enabled | Enabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `ACCESS_MALFORMED` | Malformed Access Token | Enabled | Enabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `ACCESS_MISSING` | Missing Access Token | Enabled | Enabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `BRUTE_FORCE_ATTACK_DETECTED` | Brute Force: Maximum login attempts are exceeded | Enabled | Enabled | Disabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Disabled |
| `COOKIE_LEN` | Illegal cookie length | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `DYN_PARAM_VALUE` | Illegal dynamic parameter value | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `EMPTY_PARAM_VALUE` | Illegal empty parameter value | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `ENTRY_POINT` | Illegal entry point | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `FLOW_TO_OBJ` | Illegal flow to URL | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `HEADER_LEN` | Illegal header length | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `HEADER_REPEATED` | Illegal repeated header | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `HOSTNAME_MISMATCH` | Host name mismatch | Enabled | Enabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `ILLEGAL_LOGIN` | Illegal login attempt | Enabled | Enabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `METACHAR_IN_HEADER` | Illegal meta character in header | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `MISSING_MANDATORY_HEADER` | Mandatory HTTP header is missing | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `MSG_KEY` | ASM Cookie Hijacking | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `NUM_OF_MANDATORY_PARAMS` | Illegal number of mandatory parameters | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `PARAM_NUMERIC_VALUE` | Illegal parameter numeric value | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `PARAM_VALUE_NOT_MATCHING_REGEX` | Parameter value does not comply with regular expression | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `REPEATED_PARAMETER_NAME` | Illegal repeated parameter name | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `REQUEST_TOO_LONG` | Request length exceeds defined buffer size | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `SERVER_SIDE_HOST` | Server-side access to disallowed host | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `SESSSION_ID_IN_URL` | Illegal session ID in URL | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `STATIC_PARAM_VALUE` | Illegal static parameter value | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `WEBSOCKET_BAD_REQUEST` | Bad WebSocket handshake request | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED` | Binary content found in text only WebSocket | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `WEBSOCKET_FRAME_MASKING` | Mask not found in client frame | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_FRAMING_PROTOCOL` | Failure in WebSocket framing protocol | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED` | Text content found in binary only WebSocket | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |

## Executive Summary

| Category | Critical | Warning | Info | Total |
|----------|----------|---------|------|-------|
| blocking | 0 | 9 | 0 | 9 |
| policy-builder | 0 | 0 | 3 | 3 |
| **Totals** | **0** | **9** | **3** | **12** |

- **Missing elements (in baseline, absent in target):** 8
- **Extra elements (in target, not in baseline):** 13

## Warning Findings (Configuration Drift)

### 1. blocking: enforcement_mode
- **Attribute:** `enforcement_mode`
- **Baseline:** transparent
- **This Policy:** blocking
- **Impact:** Blocking section enforcement mode changed from 'transparent' to 'blocking'.

### 2. blocking: ILLEGAL_INGRESS_OBJECT
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Login URL bypassed' (ILLEGAL_INGRESS_OBJECT) is in baseline but absent from target.

### 3. blocking: CSRF_EXPIRED
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'CSRF authentication expired' (CSRF_EXPIRED) is in baseline but absent from target.

### 4. blocking: ILLEGAL_METHOD
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal method' (ILLEGAL_METHOD) is in baseline but absent from target.

### 5. blocking: MOD_ASM_COOKIE
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Modified ASM cookie' (MOD_ASM_COOKIE) is in baseline but absent from target.

### 6. blocking: PARSER_EXPIRED_INGRESS_OBJECT
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Login URL expired' (PARSER_EXPIRED_INGRESS_OBJECT) is in baseline but absent from target.

### 7. blocking: VIRUS_DETECTED
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Virus detected' (VIRUS_DETECTED) is in baseline but absent from target.

### 8. blocking: CSRF
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'CSRF attack detected' (CSRF) is in baseline but absent from target.

### 9. blocking: MOD_DOMAIN_COOKIE
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Modified domain cookie(s)' (MOD_DOMAIN_COOKIE) is in baseline but absent from target.

## Informational Findings

### 1. policy-builder: learnFromResponses
- **Attribute:** `learnFromResponses`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Learn-from-responses setting differs from baseline.

### 2. policy-builder.cookie: enforceUnmodifiedCookies
- **Attribute:** `enforceUnmodifiedCookies`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Policy Builder cookie 'enforceUnmodifiedCookies' differs from baseline.

### 3. policy-builder.sessionsAndLogins: learnLoginPages
- **Attribute:** `learnLoginPages`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Policy Builder sessionsAndLogins 'learnLoginPages' differs from baseline.

## Blocking Section — Violations Comparison

Compares each violation's Alarm / Block / Learn flags against the baseline.
Cells marked with ⚠ differ from baseline; 🚨 indicates a critical security gap.

| ID | Violation Name | Attr | Baseline | Target | Severity |
|----|----------------|------|:--------:|:------:|----------|
| `enforcement_mode` | enforcement_mode | `enforcement_mode` | transparent | blocking | ⚠ WARNING |
| `ILLEGAL_INGRESS_OBJECT` | ILLEGAL_INGRESS_OBJECT | `(all)` | present | missing | ⚠ WARNING |
| `CSRF_EXPIRED` | CSRF_EXPIRED | `(all)` | present | missing | ⚠ WARNING |
| `ILLEGAL_METHOD` | ILLEGAL_METHOD | `(all)` | present | missing | ⚠ WARNING |
| `MOD_ASM_COOKIE` | MOD_ASM_COOKIE | `(all)` | present | missing | ⚠ WARNING |
| `PARSER_EXPIRED_INGRESS_OBJECT` | PARSER_EXPIRED_INGRESS_OBJECT | `(all)` | present | missing | ⚠ WARNING |
| `VIRUS_DETECTED` | VIRUS_DETECTED | `(all)` | present | missing | ⚠ WARNING |
| `CSRF` | CSRF | `(all)` | present | missing | ⚠ WARNING |
| `MOD_DOMAIN_COOKIE` | MOD_DOMAIN_COOKIE | `(all)` | present | missing | ⚠ WARNING |

## Extra Elements Not in Baseline

Items present in this policy but not in the baseline:

- `{'section': 'signature-sets', 'name': 'JavaScript Signatures (High/Medium Accuracy)'}`
- `{'section': 'signature-sets', 'name': 'MySQL Signatures (High/Medium Accuracy)'}`
- `{'section': 'blocking', 'id': 'SESSSION_ID_IN_URL', 'name': 'Illegal session ID in URL'}`
- `{'section': 'blocking', 'id': 'FLOW_TO_OBJ', 'name': 'Illegal flow to URL'}`
- `{'section': 'blocking', 'id': 'DYN_PARAM_VALUE', 'name': 'Illegal dynamic parameter value'}`
- `{'section': 'blocking', 'id': 'MSG_KEY', 'name': 'ASM Cookie Hijacking'}`
- `{'section': 'blocking', 'id': 'ENTRY_POINT', 'name': 'Illegal entry point'}`
- `{'section': 'blocking', 'id': 'HOSTNAME_MISMATCH', 'name': 'Host name mismatch'}`
- `{'section': 'blocking', 'id': 'SERVER_SIDE_HOST', 'name': 'Server-side access to disallowed host'}`
- `{'section': 'blocking', 'id': 'ACCESS_INVALID', 'name': 'Access token does not comply with the profile requirements'}`
- `{'section': 'blocking', 'id': 'ACCESS_MISSING', 'name': 'Missing Access Token'}`
- `{'section': 'blocking', 'id': 'ACCESS_MALFORMED', 'name': 'Malformed Access Token'}`
- `{'section': 'blocking', 'id': 'ILLEGAL_LOGIN', 'name': 'Illegal login attempt'}`

## Missing Elements From Baseline

Items expected from baseline that are absent in this policy:

- `{'section': 'blocking', 'id': 'ILLEGAL_INGRESS_OBJECT', 'name': 'Login URL bypassed'}`
- `{'section': 'blocking', 'id': 'CSRF_EXPIRED', 'name': 'CSRF authentication expired'}`
- `{'section': 'blocking', 'id': 'ILLEGAL_METHOD', 'name': 'Illegal method'}`
- `{'section': 'blocking', 'id': 'MOD_ASM_COOKIE', 'name': 'Modified ASM cookie'}`
- `{'section': 'blocking', 'id': 'PARSER_EXPIRED_INGRESS_OBJECT', 'name': 'Login URL expired'}`
- `{'section': 'blocking', 'id': 'VIRUS_DETECTED', 'name': 'Virus detected'}`
- `{'section': 'blocking', 'id': 'CSRF', 'name': 'CSRF attack detected'}`
- `{'section': 'blocking', 'id': 'MOD_DOMAIN_COOKIE', 'name': 'Modified domain cookie(s)'}`
