"""
Core detection logic for incomplete idempotency keys in bridge fulfillment functions.

The CC-1 bug pattern:
  bytes32 key = keccak256(abi.encodePacked(sourceChainId, txHash, depositId));
  // missing destChainId / block.chainid  ← flagged
  if (bridgeFulfilled[key]) revert ...;
  bridgeFulfilled[key] = true;
"""

import re
from dataclasses import dataclass
from typing import Optional

from .parser import FunctionInfo, EncodedKey, extract_functions


# Tokens that indicate the destination chain is bound into the key
_DEST_CHAIN_PATTERNS = re.compile(
    r"\b(block\.chainid|chainId|destChainId|destinationChainId|dstChainId|"
    r"targetChainId|toChainId|chainid)\b",
    re.IGNORECASE,
)

# Tokens that suggest this function is a bridge fulfillment / relay.
# No word boundaries — we want _mint(), fulfillBridge(), _handleMint(), etc.
_FULFILL_HINT_PATTERNS = re.compile(
    r"(fulfill|mint|relay|execute|claim|redeem|complete|finalize)",
    re.IGNORECASE,
)

# Source-side cross-chain parameters commonly present
_SOURCE_CHAIN_PATTERNS = re.compile(
    r"\b(sourceChainId|srcChainId|fromChainId|originChainId|sourceChain)\b",
    re.IGNORECASE,
)


@dataclass
class Finding:
    file_path: str
    function_name: str
    line: int
    rule: str               # "CC-1" or "CC-2"
    key_var: str            # CC-1: key variable name  /  CC-2: identifier param name
    guard_mapping: str      # CC-1: mapping name        /  CC-2: "(none — missing)"
    present_args: list[str] # CC-1: key args present   /  CC-2: []
    missing: list[str]      # what's flagged as missing
    severity: str = "HIGH"

    def summary(self) -> str:
        args_str = ", ".join(self.present_args) if self.present_args else "(none)"
        missing_str = ", ".join(self.missing)
        return (
            f"[{self.severity}][{self.rule}] {self.file_path}:{self.line}\n"
            f"  Function : {self.function_name}()\n"
            f"  Guard    : {self.guard_mapping}[{self.key_var}]\n"
            f"  Key args : {args_str}\n"
            f"  Missing  : {missing_str}\n"
        )

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "file": self.file_path,
            "function": self.function_name,
            "line": self.line,
            "key_variable": self.key_var,
            "guard_mapping": self.guard_mapping,
            "key_args": self.present_args,
            "missing_fields": self.missing,
        }


def _args_contain_dest_chain(args: list[str]) -> bool:
    return any(_DEST_CHAIN_PATTERNS.search(a) for a in args)


def _has_source_chain_context(func: FunctionInfo) -> bool:
    """Heuristic: function likely processes cross-chain messages if it has source chain params."""
    all_text = " ".join(func.params) + func.body
    return bool(_SOURCE_CHAIN_PATTERNS.search(all_text))


def _is_fulfillment_function(func: FunctionInfo) -> bool:
    return bool(_FULFILL_HINT_PATTERNS.search(func.name))


def _key_is_guarded(func: FunctionInfo, key_var: str) -> Optional[str]:
    """
    Return the guard mapping name if key_var is used to index into a replay guard,
    otherwise None.
    """
    for guard in func.replay_guards:
        if guard.key_var == key_var:
            return guard.mapping_name
    return None


def analyze_function(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    for ek in func.encoded_keys:
        # Only care about keys actually used as a replay guard
        guard_name = _key_is_guarded(func, ek.var_name)
        if guard_name is None:
            continue

        # Only flag if this looks like a cross-chain fulfillment context
        if not (_is_fulfillment_function(func) or _has_source_chain_context(func)):
            continue

        if _args_contain_dest_chain(ek.args):
            continue  # key is correctly bound to destination chain

        missing = ["destChainId / block.chainid"]
        findings.append(
            Finding(
                file_path=file_path,
                function_name=func.name,
                line=ek.line,
                rule="CC-1",
                key_var=ek.var_name,
                guard_mapping=guard_name,
                present_args=ek.args,
                missing=missing,
            )
        )

    return findings


def analyze_source(source: str, file_path: str) -> list[Finding]:
    from .cc2_detector import analyze_function_cc2
    functions = extract_functions(source)
    findings = []
    for func in functions:
        findings.extend(analyze_function(func, file_path))
        findings.extend(analyze_function_cc2(func, file_path))
    return findings
