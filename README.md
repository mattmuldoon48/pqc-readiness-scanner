# PQC Readiness Scanner

A lightweight Python CLI that scans a code or configuration folder for deterministic evidence of quantum-vulnerable cryptography and writes a post-quantum cryptography readiness report.

This is a practical quantum-adjacent cybersecurity project. It builds a cryptographic inventory for migration planning. It does **not** implement post-quantum algorithms, does **not** simulate quantum computing, and is **not** a production cryptographic audit.

## Why this matters

RSA, ECDSA, ECDH, Ed25519, and related public-key systems are important migration inventory targets because cryptographically relevant quantum computers would threaten their security assumptions. Organizations need to know where these algorithms appear before they can plan PQC or hybrid migrations. Inventory is the first step: certificates, TLS configs, JWT signing, SSH keys, dependencies, and application crypto code all have different owners and migration paths.

## What it scans

Rules are loaded from `src/pqc_scanner/rules/default_rules.yml` and matched deterministically against text files under the target folder. The default rules include indicators for:

- RSA private and public key PEM markers
- RSA in TLS and certificate configuration
- ECDSA, ECDH, ECC, and named elliptic curves
- Ed25519 and EdDSA references
- OpenSSL dependency or configuration usage
- JWT algorithms such as `RS256`, `ES256`, and `EdDSA`
- SSH key references such as `ssh-rsa` and `ecdsa-sha2-*`
- X.509 and certificate references

For each finding the scanner records rule ID, file path, line number, matched snippet, crypto family, usage category, severity, confidence, reason, recommendation, risk score, and risk level.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run

```bash
python -m pqc_scanner scan examples/mock_enterprise_app --out reports/mock_enterprise_app
```

With suppressions and baseline comparison:

```bash
python -m pqc_scanner scan examples/mock_enterprise_app \
  --out reports/mock_enterprise_app \
  --suppressions examples/mock_enterprise_app/.pqc-scanner-ignore.yml \
  --baseline reports/previous/crypto_inventory.json
```

Generated files:

- `crypto_inventory.json` — machine-readable inventory and summary
- `pqc_readiness_report.md` — human-readable readiness report
- `risk_summary.csv` — spreadsheet-friendly finding list
- `pqc_findings.sarif` — SARIF output for security tooling and code scanning workflows
- `baseline_diff.json` — new/resolved/unchanged finding comparison when `--baseline` is provided

## Sample output

```text
PQC Readiness Scan Complete
Files scanned: 7
Findings: 39
Highest risk: 100
json: reports/mock_enterprise_app/crypto_inventory.json
markdown: reports/mock_enterprise_app/pqc_readiness_report.md
csv: reports/mock_enterprise_app/risk_summary.csv
sarif: reports/mock_enterprise_app/pqc_findings.sarif
```

A Markdown finding row looks like:

| Risk | Severity | Rule | Location | Crypto family | Category | Evidence |
| ---: | --- | --- | --- | --- | --- | --- |
| 100 | critical | rsa_private_key_marker | auth_service.py:10 | RSA | private_key | `-----BEGIN RSA PRIVATE KEY-----` |

## Risk scoring

Risk scoring is intentionally simple and explainable:

- Higher risk: private keys, TLS/certificate configuration, authentication/JWT/signing, and production-like paths.
- Medium risk: dependencies and configuration references.
- Lower risk: documentation, examples, and README-style mentions.

Scores help triage inventory review; they are not cryptographic proof of exploitability.

## Suppressions and baselines

Suppression files are YAML documents with explicit reasons:

```yaml
suppressions:
  - rule_id: x509_certificate_reference
    file_path: README.md
    reason: Documentation-only mention in mock app README.
```

Baseline mode compares the current scan to a previous `crypto_inventory.json` and writes `baseline_diff.json` with new, resolved, and unchanged findings.


## Limitations and honesty

- Not a production cryptographic audit.
- Does not implement PQC algorithms.
- Does not prove whether a finding is reachable in runtime code.
- Does not parse every language or binary format.
- May miss generated, encrypted, remote, or dynamically assembled configuration.
- May flag benign documentation or fake examples.
- Uses deterministic local rules only; no paid APIs and no external AI calls.

Use the output to start conversations with service owners, PKI teams, platform teams, and application security reviewers.

## Roadmap

Completed:

- SARIF output for security tooling integration.
- Allowlist/suppression support for accepted findings.
- Baseline/diff mode to compare scans over time.
- GitHub Actions CI.

Future:

- Add configurable severity and risk-scoring weights.
- Add file-type-aware scanners for Terraform, Nginx, Python, and package manifests.
- Add owner/team metadata mapping for findings.
- Add a Docker image for repeatable CLI runs.

## Development

```bash
pytest
python -m pqc_scanner scan examples/mock_enterprise_app --out reports/mock_enterprise_app
```
