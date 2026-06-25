from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import ScanResult

JSON_NAME = "crypto_inventory.json"
MARKDOWN_NAME = "pqc_readiness_report.md"
CSV_NAME = "risk_summary.csv"

CSV_FIELDS = [
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


def write_reports(result: ScanResult, output_dir: Path) -> dict[str, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": output / JSON_NAME,
        "markdown": output / MARKDOWN_NAME,
        "csv": output / CSV_NAME,
    }
    paths["json"].write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["markdown"].write_text(render_markdown(result), encoding="utf-8")
    write_csv(result, paths["csv"])
    return paths


def write_csv(result: ScanResult, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for finding in result.findings:
            data = finding.model_dump() if hasattr(finding, "model_dump") else finding.dict()
            writer.writerow({field: data[field] for field in CSV_FIELDS})


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# PQC Readiness Report",
        "",
        "This report inventories deterministic indicators of quantum-vulnerable or migration-relevant cryptography.",
        "It is a lightweight discovery aid, not a production cryptographic audit and not a PQC implementation.",
        "",
        "## Scan Summary",
        "",
        f"- Target: `{result.target_path}`",
        f"- Files scanned: {result.files_scanned}",
        f"- Total findings: {result.summary.total_findings}",
        f"- Highest risk score: {result.summary.highest_risk_score}",
        f"- Average risk score: {result.summary.average_risk_score}",
        "",
        "### Counts by Severity",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ["critical", "high", "medium", "low"]:
        lines.append(f"| {severity} | {result.summary.by_severity.get(severity, 0)} |")

    lines.extend([
        "",
        "### Counts by Crypto Family",
        "",
        "| Crypto family | Count |",
        "| --- | ---: |",
    ])
    for family, count in result.summary.by_crypto_family.items():
        lines.append(f"| {escape_md(family)} | {count} |")

    lines.extend([
        "",
        "## Findings",
        "",
        "| Risk | Severity | Rule | Location | Crypto family | Category | Evidence | Recommendation |",
        "| ---: | --- | --- | --- | --- | --- | --- | --- |",
    ])
    if not result.findings:
        lines.append("| 0 | low | none | - | - | - | No findings | Continue maintaining inventory. |")
    for finding in result.findings:
        location = f"{finding.file_path}:{finding.line_number}"
        lines.append(
            "| "
            + " | ".join(
                [
                    str(finding.risk_score),
                    escape_md(finding.severity),
                    escape_md(finding.rule_id),
                    escape_md(location),
                    escape_md(finding.crypto_family),
                    escape_md(finding.usage_category),
                    f"`{escape_md(finding.matched_text)}`",
                    escape_md(finding.recommendation),
                ]
            )
            + " |"
        )

    if result.warnings:
        lines.extend(["", "## Warnings", ""])
        for warning in result.warnings:
            lines.append(f"- `{escape_md(warning.file_path)}`: {escape_md(warning.message)}")

    lines.extend([
        "",
        "## Migration Readiness Notes",
        "",
        "- Prioritize private keys, TLS/certificate paths, JWT/auth signing, and production-like infrastructure first.",
        "- Build an owner-backed crypto inventory before selecting PQC or hybrid migration paths.",
        "- Validate findings with application owners; deterministic text matches can miss generated or runtime-only crypto use.",
        "",
    ])
    return "\n".join(lines)


def escape_md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
