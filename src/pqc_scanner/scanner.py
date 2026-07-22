from __future__ import annotations

import fnmatch
import re
from collections import Counter
from pathlib import Path

from .models import Finding, ScanResult, ScanSummary, ScanWarning, path_for_report
from .rules import default_rules_path, load_rules
from .scoring import score_finding
from .suppressions import is_suppressed, load_suppressions

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules", "dist", "build"}
SKIP_FILES = {".pqc-scanner-ignore.yml", ".pqc-scanner-ignore.yaml"}
MAX_FILE_BYTES = 2_000_000


def scan_path(
    target_path: Path,
    output_dir: Path | None = None,
    rules_path: Path | None = None,
    suppressions_path: Path | None = None,
) -> ScanResult:
    target = Path(target_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")
    if not target.is_dir():
        raise NotADirectoryError(f"Target path is not a directory: {target_path}")

    output_root = Path(output_dir).resolve() if output_dir is not None else None
    if output_root is not None:
        try:
            target.relative_to(output_root)
        except ValueError:
            pass
        else:
            raise ValueError("Output directory must not be the scan target or an ancestor of it")

    rules = load_rules(rules_path)
    suppressions = load_suppressions(suppressions_path)
    compiled = [
        (rule, [re.compile(pattern, 0 if rule.case_sensitive else re.IGNORECASE) for pattern in rule.patterns])
        for rule in rules
    ]

    findings: list[Finding] = []
    warnings: list[ScanWarning] = []
    seen: set[tuple[str, int, str, str]] = set()
    files_scanned = 0

    for file_path in iter_files(target):
        if output_root is not None:
            try:
                file_path.resolve().relative_to(output_root)
                continue
            except ValueError:
                pass

        relative_path = file_path.relative_to(target)
        rel_report = path_for_report(relative_path)
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                warnings.append(ScanWarning(file_path=rel_report, message="Skipped file larger than scan limit"))
                continue
            data = file_path.read_bytes()
        except OSError as exc:
            warnings.append(ScanWarning(file_path=rel_report, message=f"Skipped unreadable file: {exc}"))
            continue

        if b"\x00" in data[:4096]:
            warnings.append(ScanWarning(file_path=rel_report, message="Skipped likely binary file"))
            continue

        text = data.decode("utf-8", errors="replace")
        files_scanned += 1
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule, regexes in compiled:
                if not path_matches(relative_path, rule.file_globs):
                    continue
                for regex in regexes:
                    for match in regex.finditer(line):
                        snippet = normalize_snippet(match.group(0) or line)
                        key = (rel_report, line_number, rule.id, snippet)
                        if key in seen:
                            continue
                        seen.add(key)
                        risk_score, risk_level = score_finding(rule, relative_path, snippet)
                        finding = Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            file_path=rel_report,
                            line_number=line_number,
                            matched_text=snippet,
                            crypto_family=rule.crypto_family,
                            usage_category=rule.usage_category,
                            severity=rule.severity,
                            confidence=rule.confidence,
                            reason=rule.reason,
                            recommendation=rule.recommendation,
                            risk_score=risk_score,
                            risk_level=risk_level,
                        )
                        if not is_suppressed(finding, suppressions):
                            findings.append(finding)

    findings.sort(key=lambda finding: (finding.file_path, finding.line_number, finding.rule_id, finding.matched_text))
    return ScanResult(
        target_path=str(target),
        rules_path=str(Path(rules_path).resolve() if rules_path else default_rules_path()),
        files_scanned=files_scanned,
        findings=findings,
        warnings=warnings,
        summary=summarize(findings),
    )


def iter_files(root: Path):
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        relative_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in relative_parts[:-1]) or path.name in SKIP_FILES:
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def path_matches(path: Path, globs: list[str]) -> bool:
    rel = path.as_posix()
    for glob in globs:
        if glob in {"*", "**/*"}:
            return True
        if path.match(glob) or fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(path.name, glob):
            return True
        if glob.startswith("**/") and fnmatch.fnmatch(path.name, glob[3:]):
            return True
    return False


def normalize_snippet(value: str) -> str:
    snippet = " ".join(value.strip().split())
    return snippet[:160]


def summarize(findings: list[Finding]) -> ScanSummary:
    severity = Counter(finding.severity for finding in findings)
    family = Counter(finding.crypto_family for finding in findings)
    category = Counter(finding.usage_category for finding in findings)
    total = len(findings)
    avg = round(sum(finding.risk_score for finding in findings) / total, 2) if total else 0.0
    high = max((finding.risk_score for finding in findings), default=0)
    return ScanSummary(
        total_findings=total,
        by_severity=dict(sorted(severity.items())),
        by_crypto_family=dict(sorted(family.items())),
        by_usage_category=dict(sorted(category.items())),
        average_risk_score=avg,
        highest_risk_score=high,
    )
