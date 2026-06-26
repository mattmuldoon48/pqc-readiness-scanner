import csv
import json
from pathlib import Path

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
