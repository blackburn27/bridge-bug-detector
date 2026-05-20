"""
Solidity source parser — extracts functions and their relevant constructs
without requiring a full compiler toolchain.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EncodedKey:
    """Represents a keccak256(abi.encodePacked(...)) call."""
    var_name: str           # variable the key is assigned to
    args: list[str]         # raw argument tokens from encodePacked
    line: int               # approximate line number in file


@dataclass
class ReplayGuard:
    """Represents a mapping(bytes32 => bool) used as a replay/idempotency guard."""
    mapping_name: str       # state variable name
    key_var: str            # variable used to index into it (may be empty if inline)
    line: int


@dataclass
class FunctionInfo:
    """All data extracted from a single Solidity function."""
    name: str
    params: list[str]               # parameter names (not types)
    typed_params: list[tuple[str, str]]  # (type, name) pairs
    body: str
    start_line: int
    modifiers: str = ""             # text between closing ) and opening { (visibility, modifiers)
    encoded_keys: list[EncodedKey] = field(default_factory=list)
    replay_guards: list[ReplayGuard] = field(default_factory=list)


def _line_of(source: str, pos: int) -> int:
    return source[:pos].count("\n") + 1


def _match_parens(source: str, open_pos: int) -> int:
    """Return the index of the closing paren matching the open paren at open_pos."""
    depth = 0
    for i in range(open_pos, len(source)):
        if source[i] == "(":
            depth += 1
        elif source[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _extract_args(inner: str) -> list[str]:
    """
    Split a comma-separated argument string respecting nested parens.
    e.g. "sourceChainId, keccak256(a, b), destId" → ["sourceChainId", "keccak256(a, b)", "destId"]
    """
    args = []
    depth = 0
    current = []
    for ch in inner:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            token = "".join(current).strip()
            if token:
                args.append(token)
            current = []
        else:
            current.append(ch)
    token = "".join(current).strip()
    if token:
        args.append(token)
    return args


def _extract_typed_params(param_str: str) -> list[tuple[str, str]]:
    """
    Extract (type, name) pairs from a function signature parameter block.
    e.g. "uint64 txid, address account" → [("uint64", "txid"), ("address", "account")]
    """
    pairs = []
    _STRIP_KEYWORDS = re.compile(r"\b(memory|calldata|storage|payable|indexed)\b")
    for param in _extract_args(param_str):
        param = _STRIP_KEYWORDS.sub("", param).strip()
        parts = param.split()
        if len(parts) >= 2:
            type_ = parts[-2].rstrip("),;")
            name = parts[-1].rstrip("),;")
            if re.match(r"^[a-zA-Z_]\w*$", name) and re.match(r"^[a-zA-Z_]\w*$", type_):
                pairs.append((type_, name))
    return pairs


def _extract_param_names(param_str: str) -> list[str]:
    """
    Extract parameter names from a function signature parameter block.
    e.g. "address token, uint256 amount, uint256 sourceChainId" → ["token", "amount", "sourceChainId"]
    """
    names = []
    # Split by comma at depth 0
    for param in _extract_args(param_str):
        param = param.strip()
        # Strip storage location keywords
        param = re.sub(r"\b(memory|calldata|storage|payable)\b", "", param).strip()
        # Last word is the name
        parts = param.split()
        if parts:
            # Remove trailing ) or , artifacts
            name = parts[-1].rstrip("),;")
            if name and re.match(r"^[a-zA-Z_]\w*$", name):
                names.append(name)
    return names


# Regex: function declaration (catches external/public/internal/private/view/pure/payable variants)
_FUNC_RE = re.compile(
    r"\bfunction\s+(\w+)\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)",
    re.DOTALL,
)

# Regex: bytes32 var = keccak256(abi.encodePacked(  — named-variable form
_KEY_ASSIGN_RE = re.compile(
    r"bytes32\s+(\w+)\s*=\s*keccak256\s*\(\s*abi\.encodePacked\s*\(",
    re.DOTALL,
)

# Regex: mapping[keccak256(abi.encodePacked(  — inline form (no temp variable)
_KEY_INLINE_RE = re.compile(
    r"\b(\w+)\[\s*keccak256\s*\(\s*abi\.encodePacked\s*\(",
    re.DOTALL,
)

# Regex: replay guard usage — mappingName[keyVar] checked or assigned
_GUARD_USE_RE = re.compile(r"\b(\w+)\[(\w+)\]")

# Regex: state-level mapping(bytes32 => bool)
_MAPPING_RE = re.compile(
    r"mapping\s*\(\s*bytes32\s*=>\s*bool\s*\)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;",
    re.DOTALL,
)


def extract_replay_guard_mappings(source: str) -> set[str]:
    """Return names of all mapping(bytes32 => bool) state variables."""
    return {m.group(1) for m in _MAPPING_RE.finditer(source)}


def extract_functions(source: str) -> list[FunctionInfo]:
    """
    Parse all top-level functions from a Solidity source string.
    Returns FunctionInfo objects with encoded keys and replay guard references populated.
    """
    guard_mappings = extract_replay_guard_mappings(source)
    functions = []

    for fm in _FUNC_RE.finditer(source):
        func_name = fm.group(1)
        param_str = fm.group(2)
        params = _extract_param_names(param_str)
        typed_params = _extract_typed_params(param_str)
        start_line = _line_of(source, fm.start())

        # Find the opening brace of the function body
        brace_search_start = fm.end()
        brace_pos = source.find("{", brace_search_start)
        if brace_pos == -1:
            continue

        # If a semicolon appears before the brace this is an abstract/interface
        # declaration with no body — skip it to avoid attaching the wrong body.
        between = source[brace_search_start:brace_pos]
        if ";" in between:
            continue

        # Match the closing brace
        depth = 0
        end_pos = -1
        for i in range(brace_pos, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    end_pos = i
                    break
        if end_pos == -1:
            continue

        body = source[brace_pos + 1 : end_pos]

        fi = FunctionInfo(
            name=func_name,
            params=params,
            typed_params=typed_params,
            body=body,
            start_line=start_line,
            modifiers=between,
        )

        # Find encoded keys inside the body — named-variable form
        for km in _KEY_ASSIGN_RE.finditer(body):
            var_name = km.group(1)
            ep_open = body.find("abi.encodePacked(", km.start())
            paren_open = body.index("(", ep_open + len("abi.encodePacked"))
            paren_close = _match_parens(body, paren_open)
            if paren_close == -1:
                continue
            inner = body[paren_open + 1 : paren_close]
            args = _extract_args(inner)
            line = start_line + body[: km.start()].count("\n")
            fi.encoded_keys.append(EncodedKey(var_name=var_name, args=args, line=line))

        # Find encoded keys — inline form: mapping[keccak256(abi.encodePacked(...))]
        for km in _KEY_INLINE_RE.finditer(body):
            mapping_name = km.group(1)
            if mapping_name not in guard_mappings:
                continue
            ep_open = body.find("abi.encodePacked(", km.start())
            paren_open = body.index("(", ep_open + len("abi.encodePacked"))
            paren_close = _match_parens(body, paren_open)
            if paren_close == -1:
                continue
            inner = body[paren_open + 1 : paren_close]
            args = _extract_args(inner)
            line = start_line + body[: km.start()].count("\n")
            # Use sentinel var name so the detector can match it to the guard
            sentinel = f"__inline_{mapping_name}"
            fi.encoded_keys.append(EncodedKey(var_name=sentinel, args=args, line=line))
            # Synthesize a guard entry for the inline key
            fi.replay_guards.append(
                ReplayGuard(mapping_name=mapping_name, key_var=sentinel, line=line)
            )

        # Find replay guard usages in the body
        for gm in _GUARD_USE_RE.finditer(body):
            mapping_name = gm.group(1)
            key_var = gm.group(2)
            if mapping_name in guard_mappings:
                line = start_line + body[: gm.start()].count("\n")
                fi.replay_guards.append(
                    ReplayGuard(mapping_name=mapping_name, key_var=key_var, line=line)
                )

        functions.append(fi)

    return functions
