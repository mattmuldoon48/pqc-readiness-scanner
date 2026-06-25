# PQC Readiness Report

This report inventories deterministic indicators of quantum-vulnerable or migration-relevant cryptography.
It is a lightweight discovery aid, not a production cryptographic audit and not a PQC implementation.

## Scan Summary

- Target: `/Users/matthewmuldoon/Desktop/resume projects/pqc-readiness-scanner/examples/mock_enterprise_app`
- Files scanned: 7
- Total findings: 39
- Highest risk score: 100
- Average risk score: 79.9

### Counts by Severity

| Severity | Count |
| --- | ---: |
| critical | 1 |
| high | 28 |
| medium | 10 |
| low | 0 |

### Counts by Crypto Family

| Crypto family | Count |
| --- | ---: |
| ECC | 5 |
| EdDSA | 2 |
| JWT public-key signatures | 11 |
| OpenSSL | 2 |
| RSA | 10 |
| SSH public-key cryptography | 2 |
| X.509 certificates | 7 |

## Findings

| Risk | Severity | Rule | Location | Crypto family | Category | Evidence | Recommendation |
| ---: | --- | --- | --- | --- | --- | --- | --- |
| 50 | high | ecc_ecdsa_ecdh_reference | README.md:4 | ECC | signing_key_agreement | `ECDSA` | Identify protocol owners and track standards-approved PQC or hybrid replacements for signing and key agreement. |
| 57 | high | ssh_classical_key_reference | README.md:4 | SSH public-key cryptography | ssh | `ssh-rsa` | Inventory host/user key locations, rotate away from legacy algorithms where possible, and track PQC SSH support. |
| 40 | medium | x509_certificate_reference | README.md:4 | X.509 certificates | certificate | `certificate` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |
| 40 | medium | x509_certificate_reference | README.md:4 | X.509 certificates | certificate | `certificates` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |
| 40 | medium | x509_certificate_reference | README.md:4 | X.509 certificates | certificate | `x509` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |
| 95 | high | rsa_tls_cert_config | auth_service.py:4 | RSA | tls_certificate | `rsa` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 100 | high | jwt_classical_algorithms | auth_service.py:6 | JWT public-key signatures | jwt_signing | `JWT_ALGORITHM` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 100 | high | jwt_classical_algorithms | auth_service.py:6 | JWT public-key signatures | jwt_signing | `RS256` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 80 | high | ecc_ecdsa_ecdh_reference | auth_service.py:8 | ECC | signing_key_agreement | `SECP256R1` | Identify protocol owners and track standards-approved PQC or hybrid replacements for signing and key agreement. |
| 100 | critical | rsa_private_key_marker | auth_service.py:10 | RSA | private_key | `-----BEGIN RSA PRIVATE KEY-----` | Locate the owning service, rotate exposed sample material if needed, and plan migration to approved PQC or hybrid key establishment/signature approaches. |
| 95 | high | rsa_tls_cert_config | auth_service.py:10 | RSA | tls_certificate | `RSA` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 95 | high | rsa_tls_cert_config | auth_service.py:12 | RSA | tls_certificate | `RSA` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 100 | high | jwt_classical_algorithms | auth_service.py:17 | JWT public-key signatures | jwt_signing | `JWT_ALGORITHM` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 80 | high | rsa_api_usage | auth_service.py:22 | RSA | application_crypto | `generate_private_key` | Review code owner, purpose, key size, data lifetime, and migration path to approved PQC/hybrid primitives. |
| 95 | high | rsa_tls_cert_config | auth_service.py:22 | RSA | tls_certificate | `rsa` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 95 | high | jwt_classical_algorithms | jwt_config.json:3 | JWT public-key signatures | jwt_signing | `ES256` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 95 | high | jwt_classical_algorithms | jwt_config.json:3 | JWT public-key signatures | jwt_signing | `jwt_algorithm` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 95 | high | ed25519_eddsa_reference | jwt_config.json:4 | EdDSA | signing | `EdDSA` | Inventory signing use and monitor migration paths to approved PQC signatures. |
| 95 | high | jwt_classical_algorithms | jwt_config.json:4 | JWT public-key signatures | jwt_signing | `ES256` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 95 | high | jwt_classical_algorithms | jwt_config.json:4 | JWT public-key signatures | jwt_signing | `EdDSA` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 95 | high | jwt_classical_algorithms | jwt_config.json:4 | JWT public-key signatures | jwt_signing | `RS256` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 45 | medium | rsa_public_key_marker | jwt_config.json:5 | RSA | public_key | `-----BEGIN PUBLIC KEY-----` | Confirm algorithm and owner; include the trust chain in PQC migration planning. |
| 60 | medium | x509_certificate_reference | jwt_config.json:6 | X.509 certificates | certificate | `x509` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |
| 70 | medium | x509_certificate_reference | nginx.conf:6 | X.509 certificates | certificate | `ssl_certificate` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |
| 80 | high | ecc_ecdsa_ecdh_reference | nginx.conf:8 | ECC | signing_key_agreement | `ECDSA` | Identify protocol owners and track standards-approved PQC or hybrid replacements for signing and key agreement. |
| 95 | high | rsa_tls_cert_config | nginx.conf:8 | RSA | tls_certificate | `ECDHE-RSA` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 52 | medium | openssl_usage | package.json:6 | OpenSSL | dependency | `node-forge` | Pin supported versions, enumerate enabled algorithms, and verify PQC/hybrid support plans for dependent services. |
| 95 | high | ed25519_eddsa_reference | package.json:10 | EdDSA | signing | `EdDSA` | Inventory signing use and monitor migration paths to approved PQC signatures. |
| 95 | high | jwt_classical_algorithms | package.json:10 | JWT public-key signatures | jwt_signing | `ES256` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 95 | high | jwt_classical_algorithms | package.json:10 | JWT public-key signatures | jwt_signing | `EdDSA` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 95 | high | jwt_classical_algorithms | package.json:10 | JWT public-key signatures | jwt_signing | `RS256` | Identify issuers, verifiers, key rotation flows, and standards-compatible PQC or hybrid token signing options. |
| 85 | high | rsa_tls_cert_config | package.json:11 | RSA | tls_certificate | `rsa` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 77 | high | ssh_classical_key_reference | package.json:11 | SSH public-key cryptography | ssh | `ssh-rsa` | Inventory host/user key locations, rotate away from legacy algorithms where possible, and track PQC SSH support. |
| 40 | medium | openssl_usage | requirements.txt:3 | OpenSSL | dependency | `pyOpenSSL` | Pin supported versions, enumerate enabled algorithms, and verify PQC/hybrid support plans for dependent services. |
| 80 | high | ecc_ecdsa_ecdh_reference | terraform.tf:8 | ECC | signing_key_agreement | `ECDSA` | Identify protocol owners and track standards-approved PQC or hybrid replacements for signing and key agreement. |
| 80 | high | ecc_ecdsa_ecdh_reference | terraform.tf:9 | ECC | signing_key_agreement | `P256` | Identify protocol owners and track standards-approved PQC or hybrid replacements for signing and key agreement. |
| 95 | high | rsa_tls_cert_config | terraform.tf:13 | RSA | tls_certificate | `rsa` | Inventory certificate issuers, validity windows, renewal automation, and hybrid/PQC certificate roadmap. |
| 70 | medium | x509_certificate_reference | terraform.tf:14 | X.509 certificates | certificate | `certificates` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |
| 70 | medium | x509_certificate_reference | terraform.tf:15 | X.509 certificates | certificate | `certificates` | Map issuing CA, certificate profile, key algorithm, consumers, and renewal automation. |

## Migration Readiness Notes

- Prioritize private keys, TLS/certificate paths, JWT/auth signing, and production-like infrastructure first.
- Build an owner-backed crypto inventory before selecting PQC or hybrid migration paths.
- Validate findings with application owners; deterministic text matches can miss generated or runtime-only crypto use.
