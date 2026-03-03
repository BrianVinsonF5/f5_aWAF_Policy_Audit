# F5 BIG-IP ASM/AWAF Security Policy Auditor

A Python CLI application that connects to an F5 BIG-IP device via the iControl
REST API, discovers all ASM/Advanced WAF security policies across every user
partition, exports each policy in XML format, compares each exported policy
against a provided baseline XML policy, and generates a detailed
compliance/drift report for each policy.

> **Read-Only Guarantee** — This tool never creates, modifies, deletes, or
> applies any configuration on the BIG-IP device. It performs only GET requests
> (plus the POST to initiate an export task, which is a read operation) and
> downloads exported policy files.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.9 or later |
| BIG-IP version | 12.1+ (ASM/AWAF module licensed and provisioned) |
| BIG-IP credentials | Account with **Resource Administrator** or **Application Security Administrator** role |
| Network access | HTTPS (port 443) to the BIG-IP management interface |

---

## Installation

```bash
# Clone or download the repository
git clone <repo-url> f5-awaf-policy-auditor
cd f5-awaf-policy-auditor

# Install Python dependencies
pip install -r requirements.txt
```

---

## Quick Start

### 1. Obtain a Baseline Policy

Export your "gold standard" policy from the BIG-IP GUI:

1. Go to **Security > Application Security > Security Policies**.
2. Select the policy to use as the baseline.
3. Click **Export** and choose **XML** format.
4. Save the file to `./baseline/corporate_baseline.xml`.

Or via the API directly:

```bash
# Trigger export
curl -sk -u admin:password \
  -X POST https://bigip/mgmt/tm/asm/tasks/export-policy \
  -H "Content-Type: application/json" \
  -d '{"filename":"baseline.xml","format":"xml","minimal":false,"policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/<POLICY_ID>"}}'

# Download after task completes
curl -sk -u admin:password \
  -H "Content-Range: 0-1048575/*" \
  https://bigip/mgmt/tm/asm/file-transfer/downloads/baseline.xml \
  -o ./baseline/corporate_baseline.xml
```

### 2. Run the Audit

**Basic usage** (will prompt for password):

```bash
python -m src.main \
  --host 192.168.1.245 \
  --username admin \
  --baseline ./baseline/corporate_baseline.xml
```

**Full options**:

```bash
python -m src.main \
  --host 10.1.1.4 \
  --username admin \
  --password 'S3cret!' \
  --baseline ./baseline/disa_stig_baseline.xml \
  --output-dir ./audit_results \
  --format both \
  --partitions Common,App1,App2 \
  --concurrent-exports 5 \
  --no-verify-ssl \
  -v
```

**Using a config file**:

```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your settings
python -m src.main --config ./config.yaml
```

**Using environment variables**:

```bash
export BIGIP_HOST=192.168.1.245
export BIGIP_USER=admin
export BIGIP_PASS='S3cret!'
python -m src.main --baseline ./baseline/corporate_baseline.xml
```

---

## CLI Reference

| Argument | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `--host` | `BIGIP_HOST` | required | BIG-IP management IP or FQDN |
| `--username` | `BIGIP_USER` | required | Admin username |
| `--password` | `BIGIP_PASS` | (prompt) | Password |
| `--baseline` | `BASELINE_POLICY` | required | Path to baseline XML policy |
| `--output-dir` | `OUTPUT_DIR` | `./output` | Output directory |
| `--format` | `REPORT_FORMAT` | `both` | `html`, `markdown`, or `both` |
| `--partitions` | `PARTITIONS` | (all) | Comma-separated partition list |
| `--export-format` | `EXPORT_FORMAT` | `xml` | `xml` or `json` |
| `--verify-ssl` / `--no-verify-ssl` | `VERIFY_SSL` | `false` | TLS verification |
| `--concurrent-exports` | `CONCURRENT_EXPORTS` | `3` | Max parallel exports |
| `-v` / `--verbose` | — | `false` | Debug logging |
| `--config` | — | `config.yaml` | Config file path |

Config file values are overridden by environment variables, which are overridden
by CLI arguments.

---

## Output Files

After a run, the `--output-dir` (default `./output`) will contain:

```
output/
├── audit_20260303T143012.log          # Full debug log
├── exports/
│   ├── Common_app1_waf_20260303T1430.xml
│   └── Common_app2_waf_20260303T1431.xml
└── reports/
    ├── app1_waf_audit_report.md       # Per-policy Markdown report
    ├── app1_waf_audit_report.html     # Per-policy HTML report (self-contained)
    ├── app2_waf_audit_report.md
    ├── app2_waf_audit_report.html
    ├── summary_audit_report.md        # Cross-policy summary
    └── summary_audit_report.html
```

---

## Compliance Scoring Methodology

Each policy starts at a score of **100.0**.

| Finding Severity | Deduction per Finding | Condition |
|------------------|-----------------------|-----------|
| **Critical**     | −5.0 points | Protection that is **enabled in baseline** is **disabled in target** |
| **Warning**      | −2.0 points | Configuration drift that reduces security posture |
| **Info**         | −0.5 points | Informational differences (e.g., baseline whitelist IPs absent in target) |

Score is floored at **0.0** and displayed with one decimal place.

A policy **passes** if its score is ≥ **90.0%**.

The CLI exits with:
- **Code 0** — all policies scored ≥ 90%
- **Code 1** — one or more policies scored < 90%, or export errors occurred

### What triggers Critical findings

| Section | Trigger |
|---------|---------|
| General Settings | `enforcementMode` is `blocking` in baseline but `transparent` in target |
| Blocking Settings | Any violation/evasion/HTTP-protocol with `block=true` in baseline but `block=false` in target |
| Attack Signatures | A signature `enabled=true` in baseline is `enabled=false` in target |
| Signature Sets | A set with `block=true` in baseline has `block=false` in target |
| Data Guard | `enabled=true` in baseline, `enabled=false` in target |
| IP Intelligence | `enabled=true` in baseline, `enabled=false` in target |
| Bot Defense | `enabled=true` in baseline, `enabled=false` in target |
| Data Guard sub-controls | Credit card / SSN protection disabled in target |

---

## Architecture

```
src/
├── main.py            # CLI entry point (argparse, orchestration)
├── bigip_client.py    # iControl REST client (token auth, chunked transfers)
├── policy_exporter.py # Policy discovery + async export workflow
├── policy_parser.py   # XML → normalized Python dict (lxml / stdlib fallback)
├── policy_comparator.py # Diff engine → ComparisonResult + DiffItem dataclasses
├── report_generator.py  # Markdown + self-contained HTML reports
└── utils.py           # Logging, retry decorator, filename helpers
```

**Key design decisions:**

- **ThreadPoolExecutor** with configurable concurrency for parallel exports
- **O(1) signature lookups** using dict keyed by `signatureId`
- **Proactive token refresh** at 80% of token lifetime — avoids mid-run 401s
- **1 MiB chunk download loop** — required by F5 file-transfer endpoint limit
- **lxml with stdlib fallback** — `lxml` is faster and more tolerant; stdlib used if unavailable
- **Credential masking** — passwords and tokens are masked in all log output

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests use XML fixtures in `tests/fixtures/`:
- `baseline_policy.xml` — reference policy with known settings
- `target_policy_drifted.xml` — deliberately modified policy with documented drifts

---

## Troubleshooting

### Authentication Failures

```
ERROR: Authentication failed for user 'admin'. Check credentials and that the
account has the Resource Administrator or Application Security Administrator role.
```

- Verify credentials with: `curl -sk -X POST https://BIGIP/mgmt/shared/authn/login -d '{"username":"admin","password":"...", "loginProviderName":"tmos"}'`
- Ensure the account is not locked out
- RADIUS/LDAP users may need `loginProviderName` changed from `tmos`

### SSL Certificate Errors

```
requests.exceptions.SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

- Add `--no-verify-ssl` (or set `verify_ssl: false` in config) for self-signed certs
- To use a CA bundle: modify `bigip_client.py` to pass `verify="/path/to/ca-bundle.pem"`

### Large Policy Downloads Truncated

The tool automatically handles the F5 1 MiB download chunk limit via `Content-Range`
headers. If a downloaded file is smaller than expected, check:
- Network interruptions (retry logic will handle transient failures)
- BIG-IP disk space on the `/var/ts/` partition

### Policy Export Timeout

```
ExportError: Export task ... timed out after 120s
```

- Large policies (hundreds of signatures) can take longer — currently not configurable
- Check BIG-IP CPU/memory under `tmsh show sys performance` during export

### Insufficient Privileges

The minimum required BIG-IP role is **Application Security Administrator**
(or Resource Administrator). To verify:

```bash
tmsh list auth user admin | grep role
```

---

## Security Considerations

1. **Credential Handling** — Passwords are never written to log files (masked as `***MASKED***`). Use environment variables or interactive prompt rather than CLI `--password` to avoid credentials appearing in shell history.

2. **Read-Only Operation** — The tool only performs read operations and export task initiation. It never calls `apply-policy`, `create`, `modify`, or `delete` endpoints. All state changes are limited to exporting a file to BIG-IP's local `/var/ts/` transfer directory.

3. **SSL Verification** — `--no-verify-ssl` is convenient but disables MITM protection. Use only on isolated management networks. Always use `--verify-ssl` in production.

4. **Token Storage** — Auth tokens are held in memory only and are never written to disk.

5. **Output Directory** — Reports may contain policy configuration details. Treat the output directory as sensitive and apply appropriate filesystem permissions.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

## Contributing

Issues and pull requests are welcome. Please ensure all tests pass before
submitting:

```bash
python -m pytest tests/ -v
```
