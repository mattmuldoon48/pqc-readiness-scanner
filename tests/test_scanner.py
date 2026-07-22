from pathlib import Path

import pytest

from pqc_scanner.scanner import scan_path
from pqc_scanner.suppressions import SuppressionLoadError, load_suppressions

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


def test_generic_pem_containers_do_not_assume_rsa(tmp_path: Path):
    (tmp_path / "keys.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----BEGIN PRIVATE KEY-----\n"
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "-----BEGIN PUBLIC KEY-----\n",
        encoding="utf-8",
    )

    result = scan_path(tmp_path)
    by_marker = {finding.matched_text: finding for finding in result.findings}

    assert by_marker["-----BEGIN RSA PRIVATE KEY-----"].rule_id == "rsa_private_key_marker"
    assert by_marker["-----BEGIN RSA PUBLIC KEY-----"].rule_id == "rsa_public_key_marker"
    assert by_marker["-----BEGIN PRIVATE KEY-----"].rule_id == "generic_private_key_marker"
    assert by_marker["-----BEGIN PUBLIC KEY-----"].rule_id == "generic_public_key_marker"
    assert by_marker["-----BEGIN PRIVATE KEY-----"].crypto_family == "Unidentified PEM key algorithm"
    assert by_marker["-----BEGIN PUBLIC KEY-----"].crypto_family == "Unidentified PEM key algorithm"


def test_suppressions_remove_matching_findings():
    unsuppressed = scan_path(EXAMPLE)
    suppressed = scan_path(EXAMPLE, suppressions_path=EXAMPLE / ".pqc-scanner-ignore.yml")

    assert any(item.file_path == "README.md" and item.rule_id == "x509_certificate_reference" for item in unsuppressed.findings)
    assert not any(item.file_path == "README.md" and item.rule_id == "x509_certificate_reference" for item in suppressed.findings)
    assert suppressed.summary.total_findings < unsuppressed.summary.total_findings


def test_suppression_entries_must_be_objects(tmp_path: Path):
    suppressions_path = tmp_path / "suppressions.yml"
    suppressions_path.write_text("suppressions:\n  - typo\n", encoding="utf-8")

    with pytest.raises(SuppressionLoadError, match="Suppression entry 1 must be an object"):
        load_suppressions(suppressions_path)


def test_empty_directory_generates_zero_findings(tmp_path: Path):
    result = scan_path(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []
    assert result.summary.total_findings == 0


def test_scan_root_named_like_skipped_directory_is_scanned(tmp_path: Path):
    target = tmp_path / "build"
    target.mkdir()
    (target / "crypto.txt").write_text("-----BEGIN RSA PRIVATE KEY-----", encoding="utf-8")

    result = scan_path(target)

    assert result.files_scanned == 1
    assert any(finding.crypto_family == "RSA" for finding in result.findings)


@pytest.mark.parametrize("output_location", ["target", "parent"])
def test_output_directory_must_not_contain_scan_target(tmp_path: Path, output_location: str):
    target = tmp_path / "target"
    target.mkdir()
    output_dir = target if output_location == "target" else tmp_path

    with pytest.raises(
        ValueError,
        match="Output directory must not be the scan target or an ancestor of it",
    ):
        scan_path(target, output_dir=output_dir)
