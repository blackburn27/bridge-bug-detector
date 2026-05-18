"""
CLI entry point for the Bridge Bug Detector.

Usage:
  bridge-detect scan                      # mass-scan all known bridge protocols
  bridge-detect scan --protocols Hop,Across
  bridge-detect scan --cache ~/.cache/bbd --out ./results
  bridge-detect file path/to/Contract.sol
  bridge-detect file contracts/           # scans all .sol files recursively
  bridge-detect file Contract.sol --json
"""

import argparse
import sys
from pathlib import Path

from .detector import analyze_source, Finding
from .reporter import print_terminal, print_json


def _collect_sol_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix == ".sol" else []
    return sorted(path.rglob("*.sol"))


def _cmd_file(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 2

    files = _collect_sol_files(target)
    if not files:
        print(f"No .sol files found at: {target}", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    for sol_file in files:
        try:
            source = sol_file.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"Warning: could not read {sol_file}: {e}", file=sys.stderr)
            continue
        all_findings.extend(analyze_source(source, str(sol_file)))

    if args.json:
        print_json(all_findings)
    else:
        print_terminal(all_findings, color=not args.no_color)

    return 1 if all_findings else 0


def _cmd_scan(args: argparse.Namespace) -> int:
    from .scanner.protocols import PROTOCOLS
    from .scanner.orchestrator import run_mass_scan

    protocols = PROTOCOLS
    if args.protocols:
        names = {n.strip().lower() for n in args.protocols.split(",")}
        protocols = [p for p in PROTOCOLS if any(n in p.name.lower() for n in names)]
        if not protocols:
            print(f"Error: no protocols matched '{args.protocols}'", file=sys.stderr)
            print(f"Known: {', '.join(p.name for p in PROTOCOLS)}", file=sys.stderr)
            return 2

    cache_dir = Path(args.cache) if args.cache else None
    output_dir = Path(args.out) if args.out else None

    results = run_mass_scan(
        protocols=protocols,
        cache_dir=cache_dir,
        output_dir=output_dir,
        verbose=not args.quiet,
    )

    total = sum(len(r.findings) for r in results)
    return 1 if total > 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bridge-detect",
        description="Detect incomplete idempotency keys in cross-chain bridge contracts.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- file subcommand ----
    p_file = sub.add_parser("file", help="Scan a single file or directory")
    p_file.add_argument("target", metavar="PATH", help="Solidity file or directory")
    p_file.add_argument("--json", action="store_true", help="Output as JSON")
    p_file.add_argument("--no-color", action="store_true", help="Disable terminal colors")

    # ---- scan subcommand ----
    p_scan = sub.add_parser("scan", help="Mass-scan all known bridge protocols")
    p_scan.add_argument(
        "--protocols",
        metavar="NAMES",
        help="Comma-separated list of protocol names to scan (default: all)",
    )
    p_scan.add_argument(
        "--cache",
        metavar="DIR",
        help="Directory for cloned repos (default: ~/.cache/bridge-bug-detector/repos)",
    )
    p_scan.add_argument(
        "--out",
        metavar="DIR",
        help="Directory for report output (default: ./scan-results)",
    )
    p_scan.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-file progress output",
    )

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "file":
        return _cmd_file(args)
    if args.command == "scan":
        return _cmd_scan(args)
    return 2


def main() -> None:
    sys.exit(run())
