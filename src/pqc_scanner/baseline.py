from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from .models import Finding, ScanResult


class BaselineDiff(BaseModel):
    baseline_path: str
    new_count: int = 0
    resolved_count: int = 0
    unchanged_count: int = 0
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)
    unchanged_fingerprints: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        if hasattr(self, "model_dump"):
            return self.model_dump()
        return self.dict()


class BaselineLoadError(ValueError):
    """Raised when a baseline inventory cannot be loaded."""


def finding_fingerprint(finding: Finding | dict[str, Any]) -> str:
    if isinstance(finding, Finding):
        data = finding.model_dump() if hasattr(finding, "model_dump") else finding.dict()
    else:
        data = finding
    parts = [
        str(data.get("rule_id", "")),
        str(data.get("file_path", "")),
        str(data.get("line_number", "")),
        str(data.get("matched_text", "")),
    ]
    return "|".join(parts)


def load_baseline_findings(path: Path) -> list[dict[str, Any]]:
    baseline_path = Path(path)
    try:
        raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineLoadError(f"Could not read baseline {baseline_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineLoadError(f"Could not parse baseline {baseline_path}: {exc}") from exc
    findings = raw.get("findings") if isinstance(raw, dict) else None
    if not isinstance(findings, list):
        raise BaselineLoadError("Baseline must be a crypto_inventory.json file with a findings list")

    validated: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        try:
            validated_finding = Finding.model_validate(finding)
        except ValidationError as exc:
            raise BaselineLoadError(f"Invalid baseline finding at index {index}: {exc}") from exc
        validated.append(validated_finding.model_dump())
    return validated


def compare_to_baseline(result: ScanResult, baseline_path: Path | None) -> BaselineDiff | None:
    if baseline_path is None:
        return None
    previous = load_baseline_findings(baseline_path)

    current_by_identity: dict[tuple[str, str, str], list[Finding]] = {}
    for finding in result.findings:
        current_by_identity.setdefault(_stable_identity(finding), []).append(finding)

    previous_by_identity: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for finding in previous:
        previous_by_identity.setdefault(_stable_identity(finding), []).append(finding)

    new_findings: list[dict[str, Any]] = []
    resolved_findings: list[dict[str, Any]] = []
    unchanged_fingerprints: list[str] = []

    for identity in sorted(current_by_identity.keys() | previous_by_identity.keys()):
        current = sorted(current_by_identity.get(identity, []), key=_finding_sort_key)
        prior = sorted(previous_by_identity.get(identity, []), key=_finding_sort_key)

        current_by_line: dict[int, list[Finding]] = {}
        for finding in current:
            current_by_line.setdefault(finding.line_number, []).append(finding)
        prior_by_line: dict[int, list[dict[str, Any]]] = {}
        for finding in prior:
            prior_by_line.setdefault(int(finding["line_number"]), []).append(finding)

        remaining_current: list[Finding] = []
        remaining_prior: list[dict[str, Any]] = []
        for line_number in sorted(current_by_line.keys() | prior_by_line.keys()):
            current_at_line = current_by_line.get(line_number, [])
            prior_at_line = prior_by_line.get(line_number, [])
            exact_count = min(len(current_at_line), len(prior_at_line))
            unchanged_fingerprints.extend(
                finding_fingerprint(finding) for finding in current_at_line[:exact_count]
            )
            remaining_current.extend(current_at_line[exact_count:])
            remaining_prior.extend(prior_at_line[exact_count:])

        moved_count = min(len(remaining_current), len(remaining_prior))
        unchanged_fingerprints.extend(
            finding_fingerprint(finding) for finding in remaining_current[:moved_count]
        )
        new_findings.extend(_finding_dict(finding) for finding in remaining_current[moved_count:])
        resolved_findings.extend(remaining_prior[moved_count:])

    return BaselineDiff(
        baseline_path=str(Path(baseline_path)),
        new_count=len(new_findings),
        resolved_count=len(resolved_findings),
        unchanged_count=len(unchanged_fingerprints),
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_fingerprints=unchanged_fingerprints,
    )


def _stable_identity(finding: Finding | dict[str, Any]) -> tuple[str, str, str]:
    data = _finding_dict(finding) if isinstance(finding, Finding) else finding
    return (
        str(data.get("rule_id", "")),
        str(data.get("file_path", "")),
        str(data.get("matched_text", "")),
    )


def _finding_sort_key(finding: Finding | dict[str, Any]) -> tuple[int, str]:
    data = _finding_dict(finding) if isinstance(finding, Finding) else finding
    return (
        int(data["line_number"]),
        json.dumps(data, sort_keys=True, separators=(",", ":")),
    )


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return finding.model_dump() if hasattr(finding, "model_dump") else finding.dict()
