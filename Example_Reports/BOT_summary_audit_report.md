# Bot Defense Profile Audit — Summary Report

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

Profiles sorted by compliance score (lowest first).

| Profile | Partition | Enforcement | Template | Virtual Servers | Score | Status | Critical | Warning | Info |
|--------|-----------|-------------|----------|-----------------|-------|--------|----------|---------|------|
| `/Common/bot-defense-device-id-generate-before-access` | Common | transparent | — | *(none)* | 68.0% | FAIL | 1 | 13 | 2 |
| `/Common/bot-defense-device-id-generate-after-access` | Common | transparent | — | *(none)* | 68.5% | FAIL | 1 | 13 | 1 |
| `/Common/bot-defense-shape-compatible` | Common | transparent | — | *(none)* | 75.0% | FAIL | 1 | 10 | 0 |
| `/Common/bot-defense` | Common | transparent | — | *(none)* | 82.5% | FAIL | 1 | 6 | 1 |
| `/Common/App1` | Common | blocking | — | `/Common/owasp-juiceshop_443_vs` (10.1.10.145:443) [direct] | 84.0% | FAIL | 0 | 8 | 0 |
| `/AWS/Baseline` | AWS | blocking | — | *(none)* | 88.0% | FAIL | 0 | 6 | 0 |
| `/Common/Baseline` | Common | transparent | — | *(none)* | 92.0% | PASS | 0 | 4 | 0 |