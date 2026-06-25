from pathlib import Path

import pytest

from pqc_scanner.rules import RuleLoadError, load_rules


def test_load_default_rules_include_required_indicators():
    rules = load_rules()
    ids = {rule.id for rule in rules}
    assert {
        "rsa_private_key_marker",
        "rsa_tls_cert_config",
        "ecc_ecdsa_ecdh_reference",
        "ed25519_eddsa_reference",
        "openssl_usage",
        "jwt_classical_algorithms",
        "ssh_classical_key_reference",
        "x509_certificate_reference",
    }.issubset(ids)
    assert [rule.id for rule in rules] == sorted(rule.id for rule in rules)


def test_invalid_rules_file_reports_validation_error(tmp_path: Path):
    bad_rules = tmp_path / "bad.yml"
    bad_rules.write_text("rules:\n  - id: missing_required_fields\n", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        load_rules(bad_rules)


def test_invalid_regex_is_rejected(tmp_path: Path):
    bad_rules = tmp_path / "bad_regex.yml"
    bad_rules.write_text(
        """
rules:
  - id: bad_regex
    name: Bad Regex
    description: invalid regex
    patterns: ['[unterminated']
    crypto_family: Test
    usage_category: config
    severity: low
    confidence: low
    reason: testing
    recommendation: fix it
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        load_rules(bad_rules)
