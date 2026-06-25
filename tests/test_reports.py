import csv
import json
from pathlib import Path

from pqc_scanner.reports import CSV_NAME, JSON_NAME, MARKDOWN_NAME, write_reports
from pqc_scanner.scanner import scan_path


def test_write_reports_creates_expected_files(tmp_path: Path):
    result = scan_path(Path("examples/mock_enterprise_app"))
    paths = write_reports(result, tmp_path)

    assert paths["json"].name == JSON_NAME
    assert paths["markdown"].name == MARKDOWN_NAME
    assert paths["csv"].name == CSV_NAME
    assert all(path.exists() for path in paths.values())

    inventory = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert inventory["summary"]["total_findings"] == len(inventory["findings"])
    assert inventory["findings"][0]["rule_id"]

    report = paths["markdown"].read_text(encoding="utf-8")
    assert "# PQC Readiness Report" in report
    assert "Migration Readiness Notes" in report
    assert "not a production cryptographic audit" in report


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
