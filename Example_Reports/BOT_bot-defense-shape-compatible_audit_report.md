# Bot Defense Profile Compliance Report for `/Common/bot-defense-shape-compatible` on `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

## Profile: `/Common/bot-defense-shape-compatible`

- **Partition:** Common
- **Enforcement Mode:** transparent
- **Baseline Profile:** bot_baseline.xml
- **Audit Date:** 2026-04-03T19:47:38Z
- **Compliance Score:** 75.0% — **FAIL** (threshold: 90%)

### Virtual Server Bindings

*No virtual server bindings found for this policy.*

## Bot Mitigation Settings

| Section | Setting | Baseline | Target | Match |
|---------|---------|----------|--------|-------|
| Core | Enforcement Mode | transparent | transparent | ✓ |
| Core | Template | balanced | balanced | ✓ |
| Core | Browser Mitigation Action | block | none | ✗ |
| Core | Allow Browser Access | enabled | enabled | ✓ |
| Core | API Access Strict Mitigation | enabled | disabled | ✗ |
| Core | DoS Attack Strict Mitigation | enabled | disabled | ✗ |
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
| Anomaly Overrides | `Selenium WebDriver` | ⚠ Added Override |
| Anomaly Overrides | `Web Rootkit` | ⚠ Added Override |
| Class Overrides | `Mobile Application` | ⚠ Added Override |
| Class Overrides | `Unknown` | ⚠ Added Override |
| Whitelist | `apple_touch_1` | ⚠ Added Override |
| Whitelist | `favicon_1` | ⚠ Added Override |

## Executive Summary

| Category | Critical | Warning | Info | Total |
|----------|----------|---------|------|-------|
| bot-defense | 1 | 10 | 0 | 11 |
| **Totals** | **1** | **10** | **0** | **11** |

- **Missing elements (in baseline, absent in target):** 0
- **Extra elements (in target, not in baseline):** 6

## Critical Findings (Protections Disabled)

### 1. bot-defense: browserMitigationAction
- **Attribute:** `browserMitigationAction`
- **Baseline:** block
- **This Policy:** none
- **Impact:** Browser mitigation action changed from 'block' to 'none'. Suspicious browsers will NOT be blocked.

## Warning Findings (Configuration Drift)

### 1. bot-defense: apiAccessStrictMitigation
- **Attribute:** `apiAccessStrictMitigation`
- **Baseline:** enabled
- **This Policy:** disabled
- **Impact:** API access strict mitigation differs from baseline.

### 2. bot-defense: dosAttackStrictMitigation
- **Attribute:** `dosAttackStrictMitigation`
- **Baseline:** enabled
- **This Policy:** disabled
- **Impact:** DoS attack strict mitigation differs from baseline.

### 3. bot-defense.whitelist: apple_touch_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Whitelist entry 'apple_touch_1' is in target but not in baseline. A new trusted source exception has been added.

### 4. bot-defense.whitelist: favicon_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Whitelist entry 'favicon_1' is in target but not in baseline. A new trusted source exception has been added.

### 5. bot-defense.overrides.anomalyOverrides: Selenium WebDriver
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'Selenium WebDriver' was added in 'Anomaly Overrides' on target profile.

### 6. bot-defense.overrides.anomalyOverrides: Web Rootkit
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'Web Rootkit' was added in 'Anomaly Overrides' on target profile.

### 7. bot-defense.overrides.classOverrides: Mobile Application
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'Mobile Application' was added in 'Class Overrides' on target profile.

### 8. bot-defense.overrides.classOverrides: Unknown
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'Unknown' was added in 'Class Overrides' on target profile.

### 9. bot-defense.overrides.whitelist: apple_touch_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'apple_touch_1' was added in 'Whitelist' on target profile.

### 10. bot-defense.overrides.whitelist: favicon_1
- **Attribute:** `present`
- **Baseline:** Disabled
- **This Policy:** Enabled
- **Impact:** Override entry 'favicon_1' was added in 'Whitelist' on target profile.

## Extra Elements Not in Baseline

Items present in this policy but not in the baseline:

- `{'section': 'bot-defense.overrides.anomalyOverrides', 'name': 'Selenium WebDriver'}`
- `{'section': 'bot-defense.overrides.anomalyOverrides', 'name': 'Web Rootkit'}`
- `{'section': 'bot-defense.overrides.classOverrides', 'name': 'Mobile Application'}`
- `{'section': 'bot-defense.overrides.classOverrides', 'name': 'Unknown'}`
- `{'section': 'bot-defense.overrides.whitelist', 'name': 'apple_touch_1'}`
- `{'section': 'bot-defense.overrides.whitelist', 'name': 'favicon_1'}`
