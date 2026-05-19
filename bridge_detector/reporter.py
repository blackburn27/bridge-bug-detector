"""
Terminal and JSON output for findings.
"""

import json
import sys
from typing import TextIO

from .detector import Finding

_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_BOLD = "\033[1m"
_RESET = "\033[0m"
_DIM = "\033[2m"


def _color(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{_RESET}" if use_color else text


def print_terminal(findings: list[Finding], out: TextIO = sys.stdout, color: bool = True) -> None:
    if not findings:
        msg = _color("No incomplete idempotency key patterns detected.", _GREEN, color)
        print(f"\n{msg}\n", file=out)
        return

    header = _color(
        f"\n  Bridge Bug Detector — {len(findings)} finding(s)\n", _BOLD, color
    )
    print(header, file=out)
    print(_color("=" * 60, _DIM, color), file=out)

    _IMPACT = {
        "CC-1": "Incomplete key → same fulfillment accepted on every dest chain → multi-mint",
        "CC-2": "No txid guard → same source tx replayed unlimited times → unbacked mint",
        "CC-3": "No chainId in signed digest → signature from Chain A replays on Chain B → unauthorized mint",
    }

    for f in findings:
        if f.severity == "HIGH":
            sev_color = _RED
        elif f.severity == "INFORMATIONAL":
            sev_color = _DIM
        else:
            sev_color = _YELLOW
        rule_tag = _color(f"[{f.rule}]", _BOLD, color)
        sev_tag = _color(f"[{f.severity}]", sev_color, color)
        loc = _color(f"{f.file_path}:{f.line}", _BOLD, color)
        print(f"\n{sev_tag}{rule_tag} {loc}", file=out)
        print(f"  Function : {_color(f.function_name + '()', _BOLD, color)}", file=out)
        print(f"  Guard    : {f.guard_mapping}[{f.key_var}]", file=out)
        args_str = ", ".join(f.present_args) if f.present_args else "(none)"
        print(f"  Key args : {args_str}", file=out)
        missing_str = ", ".join(f.missing)
        print(f"  Missing  : {_color(missing_str, sev_color, color)}", file=out)
        impact = _IMPACT.get(f.rule, "Bridge replay vulnerability")
        print(_color(f"  Impact   : {impact}", _DIM, color), file=out)

    print(f"\n{_color('=' * 60, _DIM, color)}", file=out)


def print_json(findings: list[Finding], out: TextIO = sys.stdout) -> None:
    data = {
        "findings": [f.to_dict() for f in findings],
        "total": len(findings),
    }
    json.dump(data, out, indent=2)
    out.write("\n")
