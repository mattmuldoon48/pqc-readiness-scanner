from __future__ import annotations

from pathlib import Path

from .models import Rule


SEVERITY_BASE = {
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 88,
}

HIGH_VALUE_CATEGORIES = {"private_key", "tls_certificate", "authentication", "jwt_signing", "signing"}
MEDIUM_VALUE_CATEGORIES = {"dependency", "config", "certificate", "ssh", "openssl"}
PRODUCTION_HINTS = {"prod", "production", "terraform", "nginx", "kubernetes", "helm", "cert", "pki", "auth", "service"}
DOC_HINTS = {"readme", "docs", "doc", "example", "examples", "sample", "samples"}


def score_finding(rule: Rule, relative_path: Path, matched_text: str) -> tuple[int, str]:
    path_text = relative_path.as_posix().lower()
    parts = {part.lower() for part in relative_path.parts}
    score = SEVERITY_BASE[rule.severity]

    if rule.usage_category in HIGH_VALUE_CATEGORIES:
        score += 15
    elif rule.usage_category in MEDIUM_VALUE_CATEGORIES:
        score += 7

    if any(hint in path_text for hint in PRODUCTION_HINTS):
        score += 10

    if relative_path.suffix.lower() in {".md", ".rst", ".txt"} or parts & DOC_HINTS:
        score -= 20

    lower_match = matched_text.lower()
    if "private key" in lower_match or "begin rsa private key" in lower_match:
        score += 15
    if any(token in lower_match for token in ("rs256", "es256", "eddsa", "jwt")):
        score += 10
    if any(token in lower_match for token in ("tls", "ssl", "x509", "certificate", "cert")):
        score += 8

    score = max(0, min(100, score))
    if score >= 85:
        level = "critical"
    elif score >= 65:
        level = "high"
    elif score >= 35:
        level = "medium"
    else:
        level = "low"
    return score, level
