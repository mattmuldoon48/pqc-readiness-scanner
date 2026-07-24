from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

import yaml
from pydantic import ValidationError

from .models import Rule


class RuleLoadError(ValueError):
    """Raised when a rule file cannot be parsed or validated."""


def default_rules_path() -> Path:
    with resources.as_file(resources.files("pqc_scanner") / "rules" / "default_rules.yml") as path:
        return Path(path)


def load_rules(path: Path | None = None) -> list[Rule]:
    rule_path = Path(path) if path else default_rules_path()
    try:
        with rule_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise RuleLoadError(f"Could not read rules file {rule_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"Could not parse rules file {rule_path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        raise RuleLoadError("Rules file must contain a top-level 'rules' list")

    rules: list[Rule] = []
    try:
        for item in raw["rules"]:
            rules.append(Rule(**item))
    except ValidationError as exc:
        raise RuleLoadError(f"Invalid rule definition: {exc}") from exc

    ids = [rule.id for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise RuleLoadError(f"Duplicate rule IDs: {', '.join(duplicates)}")

    for rule in rules:
        flags = 0 if rule.case_sensitive else re.IGNORECASE
        for pattern in rule.patterns:
            try:
                compiled_pattern = re.compile(pattern, flags)
            except re.error as exc:
                raise RuleLoadError(f"Invalid regex in {rule.id}: {exc}") from exc
            if compiled_pattern.search("") is not None:
                raise RuleLoadError(
                    f"Regex in {rule.id} must not match empty text: {pattern!r}"
                )

    return sorted(rules, key=lambda rule: rule.id)
