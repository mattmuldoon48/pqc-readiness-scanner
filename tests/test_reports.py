import csv
import json
from pathlib import Path

import pytest

from pqc_scanner.baseline import (
    BaselineLoadError,
    compare_to_baseline,
    finding_fingerprint,
    load_baseline_findings,
)
from pqc_scanner.reports import (
    BASELINE_DIFF_NAME,
    render_sarif,
    write_reports,
)
from pqc_scanner.scanner import scan_path


def test_nested_report_output_is_excluded_from_repeat_scans(tmp_path: Path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----", encoding="utf-8")
    output_dir = target / "reports"

    first = scan_path(target, output_dir=output_dir)
    first_paths = write_reports(first, output_dir)
    first_inventory = json.loads(first_paths["json"].read_text(encoding="utf-8"))

    repeated = scan_path(target, output_dir=output_dir)
    repeated_paths = write_reports(repeated, output_dir)
    repeated_inventory = json.loads(repeated_paths["json"].read_text(encoding="utf-8"))

    assert repeated.files_scanned == 1
    assert {finding["file_path"] for finding in repeated_inventory["findings"]} == {"key.pem"}
    assert repeated_inventory["findings"] == first_inventory["findings"]
    assert repeated_inventory["summary"] == first_inventory["summary"]



def test_csv_has_stable_header_and_one_row_per_finding(tmp_path: Path):
    result = scan_path(Path("examples/mock_enterprise_app"))
    paths = write_reports(result, tmp_path)

    with paths["csv"].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert rows
    assert list(rows[0].keys()) == [
        "rule_id",
        "file_path",
        "line_number",
        "matched_text",
        "crypto_family",
        "usage_category",
        "severity",
        "confidence",
        "risk_score",
        "risk_level",
        "reason",
        "recommendation",
    ]
    assert len(rows) == result.summary.total_findings


def test_suppression_requires_all_selectors_before_omitting_inventory_finding(tmp_path: Path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "accepted.txt").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "-----BEGIN PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (target / "production.txt").write_text("-----BEGIN RSA PRIVATE KEY-----\n", encoding="utf-8")
    policy = tmp_path / "suppressions.yml"
    policy.write_text(
        "suppressions:\n"
        "  - rule_id: 'rsa_*_key_marker'\n"
        "    file_path: accepted.txt\n"
        "    matched_text: private key\n"
        "    reason: Reviewed RSA private-key fixture only\n",
        encoding="utf-8",
    )
    before = {
        (finding.file_path, finding.line_number, finding.rule_id)
        for finding in scan_path(target).findings
    }
    removed = ("accepted.txt", 1, "rsa_private_key_marker")
    partial_matches = {
        ("accepted.txt", 2, "rsa_public_key_marker"),
        ("accepted.txt", 3, "generic_private_key_marker"),
        ("production.txt", 1, "rsa_private_key_marker"),
    }
    assert partial_matches | {removed} <= before

    result = scan_path(target, suppressions_path=policy)
    paths = write_reports(result, tmp_path / "reports")
    inventory = json.loads(paths["json"].read_text(encoding="utf-8"))
    after = {
        (finding["file_path"], finding["line_number"], finding["rule_id"])
        for finding in inventory["findings"]
    }

    assert after == before - {removed}


def test_baseline_diff_report_identifies_new_and_resolved_findings(tmp_path: Path):
    baseline_result = scan_path(Path("examples/mock_enterprise_app"))
    baseline_paths = write_reports(baseline_result, tmp_path / "baseline")

    changed_app = tmp_path / "changed_app"
    changed_app.mkdir()
    (changed_app / "new_jwt_config.json").write_text('{"jwt_algorithm": "RS256"}', encoding="utf-8")
    current_result = scan_path(changed_app)
    current_paths = write_reports(current_result, tmp_path / "current", baseline_path=baseline_paths["json"])

    assert current_paths["baseline_diff"].name == BASELINE_DIFF_NAME
    diff = json.loads(current_paths["baseline_diff"].read_text(encoding="utf-8"))
    assert diff["new_count"] >= 1
    assert diff["resolved_count"] >= 1

    report = current_paths["markdown"].read_text(encoding="utf-8")
    assert "## Baseline Diff" in report


def test_baseline_loader_preserves_valid_empty_findings_list(tmp_path: Path):
    baseline_path = tmp_path / "empty_baseline.json"
    baseline_path.write_text(json.dumps({"findings": []}), encoding="utf-8")

    assert load_baseline_findings(baseline_path) == []


@pytest.mark.parametrize(
    ("invalid_finding", "expected_context"),
    [
        ("not a finding object", "valid dictionary"),
        ({}, "rule_id"),
    ],
)
def test_baseline_loader_rejects_invalid_entries_atomically(
    tmp_path: Path, invalid_finding: object, expected_context: str
):
    scanner_result = scan_path(Path("examples/mock_enterprise_app"))
    valid_finding = scanner_result.to_dict()["findings"][0]
    baseline_path = tmp_path / "invalid_baseline.json"
    baseline_path.write_text(
        json.dumps({"findings": [valid_finding, invalid_finding]}),
        encoding="utf-8",
    )

    with pytest.raises(BaselineLoadError) as error:
        load_baseline_findings(baseline_path)

    assert "index 1" in str(error.value)
    assert expected_context in str(error.value)


def test_baseline_loader_rejects_duplicate_findings(tmp_path: Path):
    scanner_result = scan_path(Path("examples/mock_enterprise_app"))
    finding = scanner_result.to_dict()["findings"][0]
    baseline_path = tmp_path / "duplicate_baseline.json"
    baseline_path.write_text(
        json.dumps({"findings": [finding, finding]}),
        encoding="utf-8",
    )

    with pytest.raises(
        BaselineLoadError,
        match="Duplicate baseline finding at index 1; first seen at index 0",
    ):
        load_baseline_findings(baseline_path)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("line_number", 0),
        ("severity", "urgent"),
        ("risk_score", 101),
    ],
)
def test_baseline_loader_rejects_invalid_finding_fields(tmp_path: Path, field: str, invalid_value: object):
    scanner_result = scan_path(Path("examples/mock_enterprise_app"))
    finding = scanner_result.to_dict()["findings"][0]
    finding[field] = invalid_value
    baseline_path = tmp_path / "invalid_field_baseline.json"
    baseline_path.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")

    with pytest.raises(BaselineLoadError) as error:
        load_baseline_findings(baseline_path)

    message = str(error.value)
    assert "index 0" in message
    assert field in message


def _compare_occurrence_lines(tmp_path: Path, previous_lines: list[int], current_lines: list[int]):
    scanned = scan_path(Path("examples/mock_enterprise_app"))
    template = scanned.findings[0]
    previous_findings = [template.model_copy(update={"line_number": line}) for line in previous_lines]
    current_findings = [template.model_copy(update={"line_number": line}) for line in current_lines]
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"findings": [finding.model_dump() for finding in previous_findings]}),
        encoding="utf-8",
    )
    current = scanned.model_copy(update={"findings": current_findings})

    diff = compare_to_baseline(current, baseline_path)

    assert diff is not None
    return diff, current_findings


def test_baseline_diff_treats_line_movement_as_unchanged(tmp_path: Path):
    diff, current = _compare_occurrence_lines(tmp_path, [10], [25])

    assert diff.new_count == 0
    assert diff.resolved_count == 0
    assert diff.unchanged_count == 1
    assert diff.unchanged_fingerprints == [finding_fingerprint(current[0])]


def test_baseline_diff_preserves_two_moved_duplicate_occurrences(tmp_path: Path):
    diff, current = _compare_occurrence_lines(tmp_path, [20, 10], [40, 30])

    assert diff.new_findings == []
    assert diff.resolved_findings == []
    assert diff.unchanged_count == 2
    assert diff.unchanged_fingerprints == [
        finding_fingerprint(current[1]),
        finding_fingerprint(current[0]),
    ]


def test_baseline_diff_reports_surplus_when_occurrences_grow_from_two_to_three(tmp_path: Path):
    diff, current = _compare_occurrence_lines(tmp_path, [10, 20], [20, 30, 40])

    assert diff.new_count == 1
    assert diff.resolved_count == 0
    assert diff.unchanged_count == 2
    assert [finding["line_number"] for finding in diff.new_findings] == [40]
    assert diff.unchanged_fingerprints == [
        finding_fingerprint(current[0]),
        finding_fingerprint(current[1]),
    ]


def test_baseline_diff_reports_surplus_when_occurrences_shrink_from_three_to_two(tmp_path: Path):
    diff, current = _compare_occurrence_lines(tmp_path, [30, 10, 20], [40, 20])

    assert diff.new_count == 0
    assert diff.resolved_count == 1
    assert diff.unchanged_count == 2
    assert [finding["line_number"] for finding in diff.resolved_findings] == [30]
    assert diff.unchanged_fingerprints == [
        finding_fingerprint(current[1]),
        finding_fingerprint(current[0]),
    ]


def test_sarif_artifact_locations_are_uri_encoded(tmp_path: Path):
    source_dir = tmp_path / "dir #"
    source_dir.mkdir()
    (source_dir / "key.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----",
        encoding="utf-8",
    )
    result = scan_path(tmp_path)

    sarif = render_sarif(result)

    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "dir%20%23/key.pem"
