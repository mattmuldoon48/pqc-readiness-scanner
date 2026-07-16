import csv
import json
from pathlib import Path

import pytest

from pqc_scanner.baseline import BaselineLoadError, load_baseline_findings
from pqc_scanner.reports import BASELINE_DIFF_NAME, CSV_NAME, JSON_NAME, MARKDOWN_NAME, SARIF_NAME, write_reports
from pqc_scanner.scanner import scan_path


def test_write_reports_creates_expected_files(tmp_path: Path):
    result = scan_path(Path("examples/mock_enterprise_app"))
    paths = write_reports(result, tmp_path)

    assert paths["json"].name == JSON_NAME
    assert paths["markdown"].name == MARKDOWN_NAME
    assert paths["csv"].name == CSV_NAME
    assert paths["sarif"].name == SARIF_NAME
    assert all(path.exists() for path in paths.values())

    inventory = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert inventory["summary"]["total_findings"] == len(inventory["findings"])
    assert inventory["findings"][0]["rule_id"]

    report = paths["markdown"].read_text(encoding="utf-8")
    assert "# PQC Readiness Report" in report
    assert "Migration Readiness Notes" in report
    assert "not a production cryptographic audit" in report

    sarif = json.loads(paths["sarif"].read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]



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


def test_baseline_diff_report_identifies_new_and_resolved_findings(tmp_path: Path):
    baseline_result = scan_path(Path("examples/mock_enterprise_app"))
    baseline_paths = write_reports(baseline_result, tmp_path / "baseline")

    changed_app = tmp_path / "changed_app"
    changed_app.mkdir()
    (changed_app / "jwt_config.json").write_text('{"jwt_algorithm": "RS256"}', encoding="utf-8")
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
