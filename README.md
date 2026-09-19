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

Choose an output directory separate from the scan target: `--out` cannot be the target itself or an ancestor of it. A directory nested inside the target is allowed, but its entire contents are excluded from scanning, including on later runs, so generated reports do not become new findings. Reserve that directory for reports rather than source files you want scanned; the example above keeps reports outside the target altogether.

With suppressions and baseline comparison:

```bash
python -m pqc_scanner scan examples/mock_enterprise_app \
  --out reports/mock_enterprise_app \
  --suppressions examples/mock_enterprise_app/.pqc-scanner-ignore.yml \
  --baseline reports/previous/crypto_inventory.json
```

To customize detection rules, copy the bundled YAML and edit the copy before scanning:

```bash
cp src/pqc_scanner/rules/default_rules.yml custom_rules.yml
python -m pqc_scanner scan examples/mock_enterprise_app \
  --out reports/custom_rules \
  --rules custom_rules.yml
```

`--rules` replaces the bundled rule set; it does not add rules to it. Keep the bundled rules in your copy if you want to preserve their coverage. The file must contain a nonempty top-level `rules` list with unique rule IDs; use the bundled definitions as the schema examples.

Generated files:

- `crypto_inventory.json` — machine-readable inventory and summary
- `pqc_readiness_report.md` — human-readable readiness report
- `risk_summary.csv` — spreadsheet-friendly finding list
- `pqc_findings.sarif` — SARIF output for security tooling and code scanning workflows
- `baseline_diff.json` — new/resolved/unchanged finding comparison when `--baseline` is provided

Use `crypto_inventory.json` as the source of truth for automation, `pqc_readiness_report.md` for reviewer handoff, `risk_summary.csv` for sorting and owner triage, and SARIF for code-scanning integrations.

A successful scan exits with status `0` even when it finds critical issues or skips files with warnings; this signals scan completion, not a clean security assessment. For CI gates, inspect `findings` and `summary` in `crypto_inventory.json` rather than relying on the exit status alone. Review its `warnings` array, or the Markdown report's `Warnings` section, for oversized, unreadable, or likely binary files that were skipped.

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

Suppressions should be narrow and reviewable: match on `rule_id`, `file_path`, or `matched_text`, and keep the required reason specific enough for a later reviewer to decide whether the exception still applies.

Within one suppression entry, **all configured selectors must match**; separate entries are alternatives, so any matching entry suppresses the finding. `rule_id` and `file_path` use shell-style wildcard patterns, not regular expressions; paths match the target-relative path shown in the inventory. `matched_text` is a case-insensitive literal substring of the finding's matched snippet, not a pattern or a search of the whole source line. For example, combining `rule_id: rsa_private_*`, `file_path: "fixtures/*.pem"`, and `matched_text: RSA PRIVATE KEY` suppresses only findings that satisfy all three conditions; it does not suppress every finding in those files.

Baseline mode compares the current scan's findings after suppressions with the findings saved in a previous `crypto_inventory.json`, and writes `baseline_diff.json` with new, resolved, and unchanged findings. Suppressed findings are omitted from the inventory, not retained as accepted findings. Adding a suppression can therefore mark a previously reported finding as resolved without changing the source; removing a suppression can make a finding appear new when it was absent from the baseline.

Baseline identity uses `rule_id`, the target-relative `file_path`, and `matched_text`, not the line number. Moving the same match within a file can remain unchanged; renaming the file produces resolved findings at the old path and new findings at the new path. “Unchanged” means the finding identity matched, not that all metadata stayed the same: severity, confidence, and risk-score changes do not change that classification. Compare the inventories themselves when reviewing risk changes, rather than relying only on new/resolved counts.

Use the same suppression policy when generating a baseline and comparing scans if you want to isolate source changes. Review suppression-policy changes alongside the diff: new findings need owner triage, resolved findings need confirmation of actual crypto removal rather than a rename or newly applied suppression, and unchanged findings should keep their existing migration owner.


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
