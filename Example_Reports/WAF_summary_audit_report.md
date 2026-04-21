# WAF Policy Audit — Summary Report

**Source Device:** `ip-10-1-1-4.us-west-2.compute.internal` (10.1.1.4)

Policies sorted by compliance score (lowest first).

| Policy | Partition | Enforcement | Virtual Servers | Score | Status | Critical | Warning | Info |
|--------|-----------|-------------|-----------------|-------|--------|----------|---------|------|
| `/Common/GraphQL_protection` | Common | transparent | `/Common/owasp-juiceshop_443_vs` (10.1.10.145:443) [direct]<br>`/Common/dvga_443` (10.1.10.147:80) [direct] | 60.0% | FAIL | 0 | 19 | 4 |
| `/AWS/App1` | AWS | transparent | `/AWS/app1andapp2` (20.20.20.2:80) [manual] | 66.5% | FAIL | 0 | 16 | 3 |
| `/AWS/App2` | AWS | transparent | `/AWS/app1andapp2` (20.20.20.2:80) [manual] | 80.5% | FAIL | 0 | 9 | 3 |
| `/Common/example` | Common | transparent | *(none)* | 100.0% | PASS | 0 | 0 | 0 |