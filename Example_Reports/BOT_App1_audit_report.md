# Bot Defense Profile Compliance Report for `/Common/App1` on `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

## Profile: `/Common/App1`

- **Partition:** Common
- **Enforcement Mode:** blocking
- **Baseline Profile:** bot_baseline.xml
- **Audit Date:** 2026-04-03T19:47:38Z
- **Compliance Score:** 84.0% — **FAIL** (threshold: 90%)

### Virtual Server Bindings

| Virtual Server | IP Address | Port | Association | Local Traffic Policies |
|----------------|:----------:|:----:|:-----------:|------------------------|
| `/Common/owasp-juiceshop_443_vs` | 10.1.10.145 | 443 | direct | *(none)* |

## Bot Mitigation Settings

| Section | Setting | Baseline | Target | Match |
|---------|---------|----------|--------|-------|
| Core | Enforcement Mode | transparent | blocking | ✗ |
| Core | Template | balanced | balanced | ✓ |
| Core | Browser Mitigation Action | block | block | ✓ |
| Core | Allow Browser Access | enabled | enabled | ✓ |
| Core | API Access Strict Mitigation | enabled | enabled | ✓ |
| Core | DoS Attack Strict Mitigation | enabled | enabled | ✓ |
| Core | Signature Staging Upon Update | disabled | disabled | ✓ |
| Core | Cross-Domain Requests | allow-all | allow-all | ✓ |
| Advanced | Perform Challenge In Transparent | disabled | disabled | ✓ |
| Advanced | Single Page Application | disabled | disabled | ✓ |
| Advanced | Device ID Mode | generate-after-access | generate-after-access | ✓ |
| Advanced | Grace Period (seconds) | 300 | 300 | ✓ |
| Advanced | Enforcement Readiness Period (days) | 7 | 7 | ✓ |

## Whitelist (Trusted Sources)

Whitelist entries and their comparison to the baseline.

| Name | Match Type | IP Address | IP Mask | Enabled | Baseline Match |
|------|:----------:|:----------:|:-------:|:-------:|:--------------:|
| apple_touch_1 | — | — | — | — | + Added |
| favicon_1 | — | — | — | — | + Added |

## Bot Defense Overrides

Override collections found in the target profile and their comparison to baseline.

| Collection | Entry | Baseline Match |
|------------|-------|----------------|
| Anomaly Overrides | `Multiple User-Agent Headers` | ⚠ Added Override |
| Class Overrides | `Malicious Bot` | ⚠ Added Override |
| Signature Category Overrides | `E-Mail Collector` | ⚠ Added Override |
| Whitelist | `apple_touch_1` | ⚠ Added Override |
| Whitelist | `favicon_1` | ⚠ Added Override |

## Executive Summary

| Category | Critical | Warning | Info | Total |
|----------|----------|---------|------|-------|
| bot-defense | 0 | 8 | 0 | 8 |
| **Totals** | **0** | **8** | **0** | **8** |

- **Missing elements (in baseline, absent in target):** 0
- **Extra elements (in target, not in baseline):** 5

## Warning Findings (Configuration Drift)

### 1. bot-defense: enforcementMode
- **Attribute:** `enforcementMode`
- **Baseline:** transparent
- **This Policy:** blocking
- **Impact:** Bot Defense enforcement mode differs. Baseline: 'transparent', Target: 'blocking'.

### 2. bot-defense.whitelist: apple_touch_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Whitelist entry 'apple_touch_1' is in target but not in baseline. A new trusted source exception has been added.

### 3. bot-defense.whitelist: favicon_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Whitelist entry 'favicon_1' is in target but not in baseline. A new trusted source exception has been added.

### 4. bot-defense.overrides.anomalyOverrides: Multiple User-Agent Headers
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'Multiple User-Agent Headers' was added in 'Anomaly Overrides' on target profile.

### 5. bot-defense.overrides.classOverrides: Malicious Bot
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'Malicious Bot' was added in 'Class Overrides' on target profile.

### 6. bot-defense.overrides.signatureCategoryOverrides: E-Mail Collector
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'E-Mail Collector' was added in 'Signature Category Overrides' on target profile.

### 7. bot-defense.overrides.whitelist: apple_touch_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'apple_touch_1' was added in 'Whitelist' on target profile.

### 8. bot-defense.overrides.whitelist: favicon_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'favicon_1' was added in 'Whitelist' on target profile.

## Extra Elements Not in Baseline

Items present in this policy but not in the baseline:

- `{'section': 'bot-defense.overrides.anomalyOverrides', 'name': 'Multiple User-Agent Headers'}`
- `{'section': 'bot-defense.overrides.classOverrides', 'name': 'Malicious Bot'}`
- `{'section': 'bot-defense.overrides.signatureCategoryOverrides', 'name': 'E-Mail Collector'}`
- `{'section': 'bot-defense.overrides.whitelist', 'name': 'apple_touch_1'}`
- `{'section': 'bot-defense.overrides.whitelist', 'name': 'favicon_1'}`
