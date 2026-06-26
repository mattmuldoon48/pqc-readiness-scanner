from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from .models import Finding


class Suppression(BaseModel):
    rule_id: str | None = None
    file_path: str | None = None
    matched_text: str | None = None
    reason: str = Field(..., min_length=1)


class SuppressionLoadError(ValueError):
    """Raised when a suppression file cannot be parsed or validated."""


def load_suppressions(path: Path | None) -> list[Suppression]:
    if path is None:
        return []
    suppression_path = Path(path)
    try:
        raw = yaml.safe_load(suppression_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SuppressionLoadError(f"Could not read suppressions file {suppression_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SuppressionLoadError(f"Could not parse suppressions file {suppression_path}: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, dict) or not isinstance(raw.get("suppressions"), list):
        raise SuppressionLoadError("Suppression file must contain a top-level 'suppressions' list")

    try:
        suppressions = [Suppression(**item) for item in raw["suppressions"]]
    except ValidationError as exc:
        raise SuppressionLoadError(f"Invalid suppression definition: {exc}") from exc

    for suppression in suppressions:
        if not any([suppression.rule_id, suppression.file_path, suppression.matched_text]):
            raise SuppressionLoadError("Each suppression must set rule_id, file_path, or matched_text")
    return suppressions


def is_suppressed(finding: Finding, suppressions: list[Suppression]) -> bool:
    return any(matches_suppression(finding, suppression) for suppression in suppressions)


def matches_suppression(finding: Finding, suppression: Suppression) -> bool:
    if suppression.rule_id and not fnmatch.fnmatch(finding.rule_id, suppression.rule_id):
        return False
    if suppression.file_path and not fnmatch.fnmatch(finding.file_path, suppression.file_path):
        return False
    if suppression.matched_text and suppression.matched_text.lower() not in finding.matched_text.lower():
        return False
    return True
