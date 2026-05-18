"""
Mass-scan orchestrator.

Fetches all bridge protocol repos, runs the detector on each, and produces
a combined terminal summary + JSON report.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..detector import analyze_source, Finding
from .fetcher import fetch_all, sol_files_for_protocol
from .protocols import Protocol, PROTOCOLS


@dataclass
class ProtocolResult:
    protocol: Protocol
    findings: list[Finding]
    files_scanned: int
    errors: list[str] = field(default_factory=list)
    skipped: bool = False       # True if clone failed


def scan_protocol(protocol: Protocol, repo_root: Path) -> ProtocolResult:
    sol_files = sol_files_for_protocol(protocol, repo_root)
    findings: list[Finding] = []
    errors: list[str] = []

    for sol_file in sol_files:
        try:
            source = sol_file.read_text(encoding="utf-8", errors="replace")
            findings.extend(analyze_source(source, str(sol_file)))
        except OSError as e:
            errors.append(f"{sol_file}: {e}")

    return ProtocolResult(
        protocol=protocol,
        findings=findings,
        files_scanned=len(sol_files),
        errors=errors,
    )


def run_mass_scan(
    protocols: list[Protocol] | None = None,
    cache_dir: Path | None = None,
    output_dir: Path | None = None,
    verbose: bool = True,
) -> list[ProtocolResult]:
    if protocols is None:
        protocols = PROTOCOLS
    if cache_dir is None:
        cache_dir = Path.home() / ".cache" / "bridge-bug-detector" / "repos"
    if output_dir is None:
        output_dir = Path.cwd() / "scan-results"

    output_dir.mkdir(parents=True, exist_ok=True)

    # ---- Phase 1: fetch repos ------------------------------------------------
    if verbose:
        print(f"\n{'='*60}")
        print(f"  Bridge Bug Detector — Mass Scan")
        print(f"  Protocols: {len(protocols)}")
        print(f"  Cache    : {cache_dir}")
        print(f"{'='*60}\n")
        print("[ Phase 1 ] Fetching repos …")

    fetched = fetch_all(protocols, cache_dir=cache_dir, verbose=verbose)

    # ---- Phase 2: scan -------------------------------------------------------
    if verbose:
        print(f"\n[ Phase 2 ] Scanning contracts …\n")

    results: list[ProtocolResult] = []
    t0 = time.time()

    for protocol, repo_root in fetched:
        if repo_root is None:
            results.append(
                ProtocolResult(
                    protocol=protocol,
                    findings=[],
                    files_scanned=0,
                    skipped=True,
                    errors=["Clone failed"],
                )
            )
            continue

        result = scan_protocol(protocol, repo_root)
        results.append(result)

        if verbose:
            high = [f for f in result.findings if f.severity == "HIGH"]
            info = [f for f in result.findings if f.severity == "INFORMATIONAL"]
            if high:
                status = f"  \033[91m{len(high)} HIGH finding(s)\033[0m"
            elif info:
                status = f"  \033[2m{len(info)} INFORMATIONAL\033[0m"
            else:
                status = "  \033[92mclean\033[0m"
            print(f"  {protocol.name:<35} {result.files_scanned:>4} files  {status}")

    elapsed = time.time() - t0

    # ---- Phase 3: write outputs ----------------------------------------------
    _write_json(results, output_dir / "findings.json")
    _write_markdown(results, output_dir / "report.md", elapsed)

    if verbose:
        _print_summary(results, elapsed, output_dir)

    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _all_findings(results: list[ProtocolResult]) -> list[Finding]:
    out = []
    for r in results:
        out.extend(r.findings)
    return out


def _write_json(results: list[ProtocolResult], path: Path) -> None:
    data = {
        "total_findings": sum(len(r.findings) for r in results),
        "protocols": [
            {
                "name": r.protocol.name,
                "repo": r.protocol.repo_url,
                "files_scanned": r.files_scanned,
                "skipped": r.skipped,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in results
        ],
    }
    path.write_text(json.dumps(data, indent=2))


def _write_markdown(results: list[ProtocolResult], path: Path, elapsed: float) -> None:
    total = sum(len(r.findings) for r in results)
    scanned = sum(r.files_scanned for r in results)
    protocols_with_findings = [r for r in results if r.findings]

    lines = [
        "# Bridge Bug Detector — Mass Scan Report",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Protocols scanned | {len(results)} |",
        f"| Solidity files scanned | {scanned} |",
        f"| Total findings | {total} |",
        f"| Protocols with findings | {len(protocols_with_findings)} |",
        f"| Scan time | {elapsed:.1f}s |",
        "",
        "## Findings by Protocol",
        "",
    ]

    if not protocols_with_findings:
        lines.append("_No findings detected._")
    else:
        for r in protocols_with_findings:
            lines.append(f"### {r.protocol.name}")
            lines.append("")
            lines.append(f"Repo: {r.protocol.repo_url}")
            lines.append("")
            for f in r.findings:
                lines.append(f"#### `{f.function_name}()` — {f.file_path.split('/')[-1]}")
                lines.append("")
                lines.append(f"- **Severity**: {f.severity}")
                lines.append(f"- **File**: `{f.file_path}`")
                lines.append(f"- **Line**: {f.line}")
                lines.append(f"- **Guard**: `{f.guard_mapping}[{f.key_var}]`")
                lines.append(f"- **Key args**: `{', '.join(f.present_args)}`")
                lines.append(f"- **Missing**: `{', '.join(f.missing)}`")
                lines.append(
                    "- **Impact**: Without destination chain in the key, the same "
                    "fulfillment hash is accepted independently on every destination "
                    "chain → one source burn can trigger N mints."
                )
                lines.append("")

    lines += [
        "## Clean Protocols",
        "",
        "| Protocol | Files |",
        "|----------|-------|",
    ]
    for r in results:
        if not r.findings and not r.skipped:
            lines.append(f"| {r.protocol.name} | {r.files_scanned} |")

    if any(r.skipped for r in results):
        lines += [
            "",
            "## Failed Clones",
            "",
        ]
        for r in results:
            if r.skipped:
                lines.append(f"- {r.protocol.name} ({r.protocol.repo_url})")

    path.write_text("\n".join(lines))


def _print_summary(results: list[ProtocolResult], elapsed: float, output_dir: Path) -> None:
    high_findings = [f for r in results for f in r.findings if f.severity == "HIGH"]
    info_findings = [f for r in results for f in r.findings if f.severity == "INFORMATIONAL"]
    protocols_high = [r for r in results if any(f.severity == "HIGH" for f in r.findings)]
    protocols_info = [r for r in results if any(f.severity == "INFORMATIONAL" for f in r.findings)]

    print(f"\n{'='*60}")
    print(f"  Scan complete in {elapsed:.1f}s")
    print(f"  Protocols   : {len(results)}")
    print(f"  HIGH        : {len(high_findings)}")
    print(f"  INFO        : {len(info_findings)}")
    if protocols_high:
        print(f"\n  \033[91mVulnerable protocols:\033[0m")
        for r in protocols_high:
            n = sum(1 for f in r.findings if f.severity == "HIGH")
            print(f"    • {r.protocol.name} ({n} HIGH finding(s))")
    if protocols_info:
        print(f"\n  \033[2mInformational (trusted-caller delegation):\033[0m")
        for r in protocols_info:
            n = sum(1 for f in r.findings if f.severity == "INFORMATIONAL")
            print(f"    • {r.protocol.name} ({n} INFORMATIONAL)")
    print(f"\n  Results saved to: {output_dir}/")
    print(f"{'='*60}\n")
