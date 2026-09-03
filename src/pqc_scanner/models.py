from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
RiskLevel = Literal["low", "medium", "high", "critical"]


def risk_level_for_score(score: int) -> RiskLevel:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"



class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    patterns: list[str] = Field(..., min_length=1)
    crypto_family: str = Field(..., min_length=1)
    usage_category: str = Field(..., min_length=1)
    severity: Severity
    confidence: Confidence = "medium"
    reason: str = Field(..., min_length=1)
    recommendation: str = Field(..., min_length=1)
    file_globs: list[str] = Field(default_factory=lambda: ["**/*"])
    case_sensitive: bool = False

    @field_validator(
        "id",
        "name",
        "description",
        "crypto_family",
        "usage_category",
        "reason",
        "recommendation",
    )
    @classmethod
    def required_metadata_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Rule metadata fields must not be blank")
        return value

    @field_validator("patterns", mode="before")
    @classmethod
    def patterns_must_not_be_empty_or_blank(cls, value: list[str]) -> list[str]:
        if not value or any(not pattern.strip() for pattern in value):
            raise ValueError("Rule patterns must contain at least one non-blank regex")
        return value


    @field_validator("file_globs")
    @classmethod
    def file_globs_must_not_be_empty_or_blank(cls, value: list[str]) -> list[str]:
        if not value or any(not glob.strip() for glob in value):
            raise ValueError("Rule file_globs must contain at least one non-blank glob")
        return value



class Finding(BaseModel):
    rule_id: str
    rule_name: str
    file_path: str
    line_number: int = Field(..., ge=1)
    matched_text: str
    crypto_family: str
    usage_category: str
    severity: Severity
    confidence: Confidence
    reason: str
    recommendation: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel

    @field_validator(
        "rule_id",
        "rule_name",
        "file_path",
        "matched_text",
        "crypto_family",
        "usage_category",
        "reason",
        "recommendation",
    )
    @classmethod
    def required_text_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Finding text fields must not be blank")
        return value

    @model_validator(mode="after")
    def risk_level_must_match_score(self) -> "Finding":
        expected = risk_level_for_score(self.risk_score)
        if self.risk_level != expected:
            raise ValueError(
                f"risk_level must be {expected!r} for risk_score {self.risk_score}"
            )
        return self


class ScanWarning(BaseModel):
    file_path: str
    message: str


class ScanSummary(BaseModel):
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_crypto_family: dict[str, int] = Field(default_factory=dict)
    by_usage_category: dict[str, int] = Field(default_factory=dict)
    average_risk_score: float = 0.0
    highest_risk_score: int = 0


class ScanResult(BaseModel):
    tool: str = "pqc-readiness-scanner"
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    target_path: str
    rules_path: str
    files_scanned: int
    findings: list[Finding]
    warnings: list[ScanWarning] = Field(default_factory=list)
    summary: ScanSummary

    def to_dict(self) -> dict[str, Any]:
        if hasattr(self, "model_dump"):
            return self.model_dump()
        return self.dict()


def path_for_report(path: Path) -> str:
    return path.as_posix()
