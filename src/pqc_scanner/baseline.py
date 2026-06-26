from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

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
    return [finding for finding in findings if isinstance(finding, dict)]


def compare_to_baseline(result: ScanResult, baseline_path: Path | None) -> BaselineDiff | None:
    if baseline_path is None:
        return None
    previous = load_baseline_findings(baseline_path)
    current_by_fp = {finding_fingerprint(finding): finding for finding in result.findings}
    previous_by_fp = {finding_fingerprint(finding): finding for finding in previous}

    current_keys = set(current_by_fp)
    previous_keys = set(previous_by_fp)
    new_keys = sorted(current_keys - previous_keys)
    resolved_keys = sorted(previous_keys - current_keys)
    unchanged_keys = sorted(current_keys & previous_keys)

    return BaselineDiff(
        baseline_path=str(Path(baseline_path)),
        new_count=len(new_keys),
        resolved_count=len(resolved_keys),
        unchanged_count=len(unchanged_keys),
        new_findings=[_finding_dict(current_by_fp[key]) for key in new_keys],
        resolved_findings=[previous_by_fp[key] for key in resolved_keys],
        unchanged_fingerprints=unchanged_keys,
    )


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return finding.model_dump() if hasattr(finding, "model_dump") else finding.dict()
