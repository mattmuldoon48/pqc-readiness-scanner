from pathlib import Path

from pqc_scanner.scanner import scan_path

EXAMPLE = Path("examples/mock_enterprise_app")


def test_scan_detects_required_crypto_families():
    result = scan_path(EXAMPLE)
    rule_ids = {finding.rule_id for finding in result.findings}

    assert result.files_scanned == 7
    assert result.summary.total_findings >= 20
    assert "rsa_private_key_marker" in rule_ids
    assert "rsa_tls_cert_config" in rule_ids
    assert "ecc_ecdsa_ecdh_reference" in rule_ids
    assert "ed25519_eddsa_reference" in rule_ids
    assert "openssl_usage" in rule_ids
    assert "jwt_classical_algorithms" in rule_ids
    assert "ssh_classical_key_reference" in rule_ids
    assert "x509_certificate_reference" in rule_ids


def test_findings_have_required_fields_and_relative_paths():
    result = scan_path(EXAMPLE)
    finding = next(item for item in result.findings if item.rule_id == "jwt_classical_algorithms")

    assert finding.file_path in {"auth_service.py", "jwt_config.json", "package.json"}
    assert finding.line_number >= 1
    assert finding.matched_text
    assert finding.crypto_family
    assert finding.usage_category
    assert finding.severity in {"low", "medium", "high", "critical"}
    assert finding.confidence in {"low", "medium", "high"}
    assert finding.reason
    assert finding.recommendation


def test_scoring_prioritizes_private_keys_over_readme_mentions():
    result = scan_path(EXAMPLE)
    private_key = next(item for item in result.findings if item.rule_id == "rsa_private_key_marker")
    readme = next(item for item in result.findings if item.file_path == "README.md")

    assert private_key.risk_score >= 85
    assert private_key.risk_level == "critical"
    assert readme.risk_score < private_key.risk_score


def test_empty_directory_generates_zero_findings(tmp_path: Path):
    result = scan_path(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []
    assert result.summary.total_findings == 0
