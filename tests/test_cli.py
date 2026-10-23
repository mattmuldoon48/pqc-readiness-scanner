import json
import os
import subprocess
import sys
from pathlib import Path


def test_python_module_cli_scan_generates_reports(tmp_path: Path):
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pqc_scanner",
            "scan",
            "examples/mock_enterprise_app",
            "--out",
            str(tmp_path),
        ],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )

    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert (tmp_path / "crypto_inventory.json").exists()
    assert (tmp_path / "pqc_readiness_report.md").exists()
    assert (tmp_path / "risk_summary.csv").exists()
    assert (tmp_path / "pqc_findings.sarif").exists()

    inventory = json.loads((tmp_path / "crypto_inventory.json").read_text(encoding="utf-8"))
    assert inventory["summary"]["total_findings"] > 0
    assert "PQC Readiness Scan Complete" in completed.stdout


def test_cli_missing_target_exits_nonzero(tmp_path: Path):
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    completed = subprocess.run(
        [sys.executable, "-m", "pqc_scanner", "scan", "does-not-exist", "--out", str(tmp_path)],
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )

    assert completed.returncode == 1
    assert "does not exist" in completed.stdout


def test_cli_invalid_pattern_type_reports_configuration_error(tmp_path: Path):
    target = tmp_path / "app"
    target.mkdir()
    (target / "crypto.txt").write_text("RSA\n", encoding="utf-8")
    rules = tmp_path / "rules.yml"
    rules.write_text(json.dumps({"rules": [{
        "id": "rsa_marker",
        "name": "RSA marker",
        "description": "Find RSA references",
        "patterns": ["RSA", 123],
        "crypto_family": "RSA",
        "usage_category": "config",
        "severity": "high",
        "reason": "Inventory",
        "recommendation": "Review",
    }]}), encoding="utf-8")
    output = tmp_path / "reports"
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"

    completed = subprocess.run(
        [
            sys.executable, "-m", "pqc_scanner", "scan", str(target),
            "--rules", str(rules), "--out", str(output),
        ],
        check=False, text=True, capture_output=True, env=env,
    )

    assert completed.returncode == 1
    assert "patterns" in completed.stdout
    assert "Traceback" not in completed.stderr
    assert not output.exists()
