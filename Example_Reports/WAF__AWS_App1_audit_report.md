# WAF Policy Compliance Report for `/AWS/App1` on `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

## Policy: `/AWS/App1`

- **Partition:** AWS
- **Enforcement Mode:** transparent
- **Baseline Policy:** baseline.xml
- **Audit Date:** 2026-04-03T19:48:05Z
- **Compliance Score:** 66.5% — **FAIL** (threshold: 90%)

### Virtual Server Bindings

| Virtual Server | IP Address | Port | Association | Local Traffic Policies |
|----------------|:----------:|:----:|:-----------:|------------------------|
| `/AWS/app1andapp2` | 20.20.20.2 | 80 | manual | `/AWS/AWS_ASM_Apply` |

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
Template was set to POLICY_TEMPLATE_FUNDAMENTAL.
Active was set to false.
Differentiate between HTTP and HTTPS URLs was set to Protocol Specific.
Policy Name was set to /AWS/App1.
Passive Mode was set to disabled.
Enforcement Mode was set to Blocking. |

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
| Parameter | Learn Parameters | Compact | When Violation Detected | ⚠ |
| Parameter | Maximum Parameters | 100 | 10000 | ⚠ |
| Parameter | Parameter Level | global | global | ✓ |
| Parameter | Collapse Parameters | Enabled | Enabled | ✓ |
| Parameter | Classify Parameters | Enabled | Disabled | ⚠ |
| URL | Learn URLs | Compact | Never | ⚠ |
| URL | Learn WebSocket URLs | Always | Never | ⚠ |
| URL | Maximum URLs | 100 | 10000 | ⚠ |
| URL | Collapse URLs | Disabled | Disabled | ✓ |
| URL | Classify URLs | Enabled | Disabled | ⚠ |
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
| `CROSS_ORIGIN_REQUEST` | Illegal cross-origin request | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `GWT_FORMAT_SETTING` | GWT data does not comply with format settings | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `HEADER_LEN` | Illegal header length | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `HEADER_REPEATED` | Illegal repeated header | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `HOSTNAME_MISMATCH` | Host name mismatch | Enabled | Enabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `ILLEGAL_INGRESS_OBJECT` | Login URL bypassed | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `ILLEGAL_REQUEST_CONTENT_TYPE` | Illegal request content type | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `ILLEGAL_SOAP_ATTACHMENT` | Illegal attachment in SOAP message | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `JSON_FORMAT_SETTING` | JSON data does not comply with format settings | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `MALFORMED_GWT` | Malformed GWT data | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `METACHAR_IN_DEF_PARAM` | Illegal meta character in value | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `METACHAR_IN_OBJ` | Illegal meta character in URL | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `METACHAR_IN_PARAM_NAME` | Illegal meta character in parameter name | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `MISSING_MANDATORY_HEADER` | Mandatory HTTP header is missing | Enabled | Enabled | Enabled | Enabled | ✓ Match | A:Enabled B:Enabled L:Enabled |
| `MOD_DOMAIN_COOKIE` | Modified domain cookie(s) | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `MULTI_PART_PARAM_VAL` | Null in multi-part parameter value | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `OBJ_DOESNT_EXIST` | Illegal URL | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `PARAM` | Illegal parameter | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `PARAM_DATA_TYPE` | Illegal parameter data type | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `PARAM_VALUE_LEN` | Illegal parameter value length | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `PARSER_EXPIRED_INGRESS_OBJECT` | Login URL expired | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `PARSER_FAILED_SOAP_SECURITY` | Web Services Security failure | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `PLAINTEXT_FORMAT_SETTING` | Plain text data does not comply with format settings | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `QS_OR_POST_DATA` | Illegal query string or POST data | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `REQUEST_TOO_LONG` | Request length exceeds defined buffer size | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `SERVER_SIDE_HOST` | Server-side access to disallowed host | Enabled | Enabled | Enabled | Enabled | — N/A | *(not in baseline)* |
| `SOAP_METHOD_NOT_ALLOWED` | SOAP method not allowed | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `VIRUS_DETECTED` | Virus detected | Disabled | Disabled | Disabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Disabled |
| `WEBSOCKET_BAD_REQUEST` | Bad WebSocket handshake request | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_FRAME_MASKING` | Mask not found in client frame | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `WEBSOCKET_FRAMING_PROTOCOL` | Failure in WebSocket framing protocol | Disabled | Disabled | Enabled | Enabled | ✓ Match | A:Disabled B:Disabled L:Enabled |
| `XML_FORMAT_SETTING` | XML data does not comply with format settings | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |
| `XML_WSDL` | XML data does not comply with schema or WSDL document | Disabled | Disabled | Disabled | Enabled | — N/A | *(not in baseline)* |

## Executive Summary

| Category | Critical | Warning | Info | Total |
|----------|----------|---------|------|-------|
| blocking | 0 | 14 | 0 | 14 |
| policy-builder | 0 | 2 | 3 | 5 |
| **Totals** | **0** | **16** | **3** | **19** |

- **Missing elements (in baseline, absent in target):** 13
- **Extra elements (in target, not in baseline):** 22

## Warning Findings (Configuration Drift)

### 1. blocking: enforcement_mode
- **Attribute:** `enforcement_mode`
- **Baseline:** transparent
- **This Policy:** blocking
- **Impact:** Blocking section enforcement mode changed from 'transparent' to 'blocking'.

### 2. blocking: WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Binary content found in text only WebSocket' (WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED) is in baseline but absent from target.

### 3. blocking: REPEATED_PARAMETER_NAME
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal repeated parameter name' (REPEATED_PARAMETER_NAME) is in baseline but absent from target.

### 4. blocking: CSRF_EXPIRED
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'CSRF authentication expired' (CSRF_EXPIRED) is in baseline but absent from target.

### 5. blocking: ILLEGAL_METHOD
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal method' (ILLEGAL_METHOD) is in baseline but absent from target.

### 6. blocking: MOD_ASM_COOKIE
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Modified ASM cookie' (MOD_ASM_COOKIE) is in baseline but absent from target.

### 7. blocking: PARAM_NUMERIC_VALUE
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal parameter numeric value' (PARAM_NUMERIC_VALUE) is in baseline but absent from target.

### 8. blocking: EMPTY_PARAM_VALUE
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal empty parameter value' (EMPTY_PARAM_VALUE) is in baseline but absent from target.

### 9. blocking: PARAM_VALUE_NOT_MATCHING_REGEX
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Parameter value does not comply with regular expression' (PARAM_VALUE_NOT_MATCHING_REGEX) is in baseline but absent from target.

### 10. blocking: METACHAR_IN_HEADER
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal meta character in header' (METACHAR_IN_HEADER) is in baseline but absent from target.

### 11. blocking: STATIC_PARAM_VALUE
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal static parameter value' (STATIC_PARAM_VALUE) is in baseline but absent from target.

### 12. blocking: NUM_OF_MANDATORY_PARAMS
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Illegal number of mandatory parameters' (NUM_OF_MANDATORY_PARAMS) is in baseline but absent from target.

### 13. blocking: WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'Text content found in binary only WebSocket' (WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED) is in baseline but absent from target.

### 14. blocking: CSRF
- **Attribute:** `(all)`
- **Baseline:** present
- **This Policy:** missing
- **Impact:** Blocking violation 'CSRF attack detected' (CSRF) is in baseline but absent from target.

### 15. policy-builder.parameter: learnParameters
- **Attribute:** `learnParameters`
- **Baseline:** Compact
- **This Policy:** When Violation Detected
- **Impact:** Policy Builder parameter 'learnParameters' differs from baseline.

### 16. policy-builder.url: learnUrls
- **Attribute:** `learnUrls`
- **Baseline:** Compact
- **This Policy:** Never
- **Impact:** Policy Builder url 'learnUrls' differs from baseline.

## Informational Findings

### 1. policy-builder.parameter: classifyParameters
- **Attribute:** `classifyParameters`
- **Baseline:** Enabled
- **This Policy:** Disabled
- **Impact:** Policy Builder parameter 'classifyParameters' differs from baseline.

### 2. policy-builder.url: learnWebsocketUrls
- **Attribute:** `learnWebsocketUrls`
- **Baseline:** Always
- **This Policy:** Never
- **Impact:** Policy Builder url 'learnWebsocketUrls' differs from baseline.

### 3. policy-builder.url: classifyUrls
- **Attribute:** `classifyUrls`
- **Baseline:** Enabled
- **This Policy:** Disabled
- **Impact:** Policy Builder url 'classifyUrls' differs from baseline.

## Blocking Section — Violations Comparison

Compares each violation's Alarm / Block / Learn flags against the baseline.
Cells marked with ⚠ differ from baseline; 🚨 indicates a critical security gap.

| ID | Violation Name | Attr | Baseline | Target | Severity |
|----|----------------|------|:--------:|:------:|----------|
| `enforcement_mode` | enforcement_mode | `enforcement_mode` | transparent | blocking | ⚠ WARNING |
| `WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED` | WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED | `(all)` | present | missing | ⚠ WARNING |
| `REPEATED_PARAMETER_NAME` | REPEATED_PARAMETER_NAME | `(all)` | present | missing | ⚠ WARNING |
| `CSRF_EXPIRED` | CSRF_EXPIRED | `(all)` | present | missing | ⚠ WARNING |
| `ILLEGAL_METHOD` | ILLEGAL_METHOD | `(all)` | present | missing | ⚠ WARNING |
| `MOD_ASM_COOKIE` | MOD_ASM_COOKIE | `(all)` | present | missing | ⚠ WARNING |
| `PARAM_NUMERIC_VALUE` | PARAM_NUMERIC_VALUE | `(all)` | present | missing | ⚠ WARNING |
| `EMPTY_PARAM_VALUE` | EMPTY_PARAM_VALUE | `(all)` | present | missing | ⚠ WARNING |
| `PARAM_VALUE_NOT_MATCHING_REGEX` | PARAM_VALUE_NOT_MATCHING_REGEX | `(all)` | present | missing | ⚠ WARNING |
| `METACHAR_IN_HEADER` | METACHAR_IN_HEADER | `(all)` | present | missing | ⚠ WARNING |
| `STATIC_PARAM_VALUE` | STATIC_PARAM_VALUE | `(all)` | present | missing | ⚠ WARNING |
| `NUM_OF_MANDATORY_PARAMS` | NUM_OF_MANDATORY_PARAMS | `(all)` | present | missing | ⚠ WARNING |
| `WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED` | WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED | `(all)` | present | missing | ⚠ WARNING |
| `CSRF` | CSRF | `(all)` | present | missing | ⚠ WARNING |

## Extra Elements Not in Baseline

Items present in this policy but not in the baseline:

- `{'section': 'blocking', 'id': 'ILLEGAL_SOAP_ATTACHMENT', 'name': 'Illegal attachment in SOAP message'}`
- `{'section': 'blocking', 'id': 'PARSER_FAILED_SOAP_SECURITY', 'name': 'Web Services Security failure'}`
- `{'section': 'blocking', 'id': 'XML_FORMAT_SETTING', 'name': 'XML data does not comply with format settings'}`
- `{'section': 'blocking', 'id': 'XML_WSDL', 'name': 'XML data does not comply with schema or WSDL document'}`
- `{'section': 'blocking', 'id': 'SOAP_METHOD_NOT_ALLOWED', 'name': 'SOAP method not allowed'}`
- `{'section': 'blocking', 'id': 'METACHAR_IN_DEF_PARAM', 'name': 'Illegal meta character in value'}`
- `{'section': 'blocking', 'id': 'METACHAR_IN_PARAM_NAME', 'name': 'Illegal meta character in parameter name'}`
- `{'section': 'blocking', 'id': 'METACHAR_IN_OBJ', 'name': 'Illegal meta character in URL'}`
- `{'section': 'blocking', 'id': 'JSON_FORMAT_SETTING', 'name': 'JSON data does not comply with format settings'}`
- `{'section': 'blocking', 'id': 'MULTI_PART_PARAM_VAL', 'name': 'Null in multi-part parameter value'}`
- `{'section': 'blocking', 'id': 'PARAM', 'name': 'Illegal parameter'}`
- `{'section': 'blocking', 'id': 'QS_OR_POST_DATA', 'name': 'Illegal query string or POST data'}`
- `{'section': 'blocking', 'id': 'OBJ_DOESNT_EXIST', 'name': 'Illegal URL'}`
- `{'section': 'blocking', 'id': 'PARAM_DATA_TYPE', 'name': 'Illegal parameter data type'}`
- `{'section': 'blocking', 'id': 'PARAM_VALUE_LEN', 'name': 'Illegal parameter value length'}`
- `{'section': 'blocking', 'id': 'ILLEGAL_REQUEST_CONTENT_TYPE', 'name': 'Illegal request content type'}`
- `{'section': 'blocking', 'id': 'MALFORMED_GWT', 'name': 'Malformed GWT data'}`
- `{'section': 'blocking', 'id': 'GWT_FORMAT_SETTING', 'name': 'GWT data does not comply with format settings'}`
- `{'section': 'blocking', 'id': 'CROSS_ORIGIN_REQUEST', 'name': 'Illegal cross-origin request'}`
- `{'section': 'blocking', 'id': 'PLAINTEXT_FORMAT_SETTING', 'name': 'Plain text data does not comply with format settings'}`
- `{'section': 'blocking', 'id': 'HOSTNAME_MISMATCH', 'name': 'Host name mismatch'}`
- `{'section': 'blocking', 'id': 'SERVER_SIDE_HOST', 'name': 'Server-side access to disallowed host'}`

## Missing Elements From Baseline

Items expected from baseline that are absent in this policy:

- `{'section': 'blocking', 'id': 'WEBSOCKET_BINARY_MESSAGE_NOT_ALLOWED', 'name': 'Binary content found in text only WebSocket'}`
- `{'section': 'blocking', 'id': 'REPEATED_PARAMETER_NAME', 'name': 'Illegal repeated parameter name'}`
- `{'section': 'blocking', 'id': 'CSRF_EXPIRED', 'name': 'CSRF authentication expired'}`
- `{'section': 'blocking', 'id': 'ILLEGAL_METHOD', 'name': 'Illegal method'}`
- `{'section': 'blocking', 'id': 'MOD_ASM_COOKIE', 'name': 'Modified ASM cookie'}`
- `{'section': 'blocking', 'id': 'PARAM_NUMERIC_VALUE', 'name': 'Illegal parameter numeric value'}`
- `{'section': 'blocking', 'id': 'EMPTY_PARAM_VALUE', 'name': 'Illegal empty parameter value'}`
- `{'section': 'blocking', 'id': 'PARAM_VALUE_NOT_MATCHING_REGEX', 'name': 'Parameter value does not comply with regular expression'}`
- `{'section': 'blocking', 'id': 'METACHAR_IN_HEADER', 'name': 'Illegal meta character in header'}`
- `{'section': 'blocking', 'id': 'STATIC_PARAM_VALUE', 'name': 'Illegal static parameter value'}`
- `{'section': 'blocking', 'id': 'NUM_OF_MANDATORY_PARAMS', 'name': 'Illegal number of mandatory parameters'}`
- `{'section': 'blocking', 'id': 'WEBSOCKET_TEXT_MESSAGE_NOT_ALLOWED', 'name': 'Text content found in binary only WebSocket'}`
- `{'section': 'blocking', 'id': 'CSRF', 'name': 'CSRF attack detected'}`
