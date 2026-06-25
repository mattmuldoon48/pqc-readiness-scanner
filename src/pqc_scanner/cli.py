from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .reports import write_reports
from .rules import RuleLoadError
from .scanner import scan_path

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pqc_scanner", description="Scan folders for PQC migration-relevant cryptography indicators.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a target folder")
    scan.add_argument("target_path", type=Path, help="folder to scan")
    scan.add_argument("--out", required=True, type=Path, dest="output_dir", help="directory for generated reports")
    scan.add_argument("--rules", type=Path, default=None, help="optional YAML rules file")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args.target_path, args.output_dir, args.rules)
    parser.error("unknown command")
    return 2


def run_scan(target_path: Path, output_dir: Path, rules_path: Path | None = None) -> int:
    try:
        with console.status("Scanning for cryptographic indicators..."):
            result = scan_path(target_path, output_dir=output_dir, rules_path=rules_path)
            paths = write_reports(result, output_dir)
    except (FileNotFoundError, NotADirectoryError, RuleLoadError, OSError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        return 1

    console.print("[bold green]PQC Readiness Scan Complete[/bold green]")
    table = Table(title="PQC Readiness Scan Complete")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Files scanned", str(result.files_scanned))
    table.add_row("Findings", str(result.summary.total_findings))
    table.add_row("Highest risk", str(result.summary.highest_risk_score))
    console.print(table)
    for label, path in paths.items():
        console.print(f"[green]{label}[/green]: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
