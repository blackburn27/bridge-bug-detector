"""
CC-4 detector: ecrecover return value not checked against address(0).

The bug pattern:
  function mint(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
      bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));
      address signer = ecrecover(hash, v, r, s);
      require(signer == trustedSigner, "bad sig");   // ← no address(0) check
      _mint(to, amount);
  }

ecrecover() returns address(0) for any invalid or malformed signature. If
trustedSigner is uninitialised (Solidity default: address(0)), or if the
signer storage slot is ever zeroed out, any garbage signature will pass
verification because ecrecover returns address(0) == trustedSigner.

Even when trustedSigner is set, a missing null check means the contract
silently accepts broken signatures rather than reverting with a clear error,
which can mask downstream exploit chains.

Safe patterns (skipped):
  - require(signer != address(0)) / require(recovered != address(0))
  - if (signer == address(0)) revert ... (inverse form)
  - address(0) / ZERO_ADDRESS comparison anywhere in the function body
  - ECDSA.recover() — OZ reverts internally on address(0)
  - SignatureChecker.isValidSignatureNow — handles null internally

Known limitation: if ecrecover lives in an internal helper (e.g. recoverSigner)
and the calling bridge function doesn't null-check the return value, this
detector does not flag it (cross-function analysis is out of scope).
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Raw ecrecover call (the only form that can return address(0) silently)
# ---------------------------------------------------------------------------

_ECRECOVER_RE = re.compile(r"\becrecover\s*\(")

# ---------------------------------------------------------------------------
# Safe patterns — any of these suppress the finding
# ---------------------------------------------------------------------------

# OZ ECDSA.recover / SignatureChecker revert internally on address(0)
_SAFE_ECDSA_RE = re.compile(
    r"\b(ECDSA\.recover|SignatureChecker\.isValidSignatureNow)\s*\(",
    re.IGNORECASE,
)

# Null-address check in the function body (any form)
_NULL_CHECK_RE = re.compile(
    r"!=\s*address\s*\(\s*0\s*\)"        # != address(0)
    r"|!=\s*address\s*\(0x0+\)"          # != address(0x000...0)
    r"|address\s*\(\s*0\s*\)\s*!="       # address(0) != x (flipped)
    r"|==\s*address\s*\(\s*0\s*\)"       # == address(0) [revert/if branch]
    r"|address\s*\(\s*0\s*\)\s*=="       # address(0) == x (flipped)
    r"|\bZERO_ADDRESS\b",                # named constant convention
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Bridge / auth function name hints
# ---------------------------------------------------------------------------

_SIG_FUNC_RE = re.compile(
    r"(mint|claim|redeem|fulfill|relay|execute|bridge|withdraw|wrap"
    r"|transfer|deliver|process|receive|finalize|complete|unlock|submit|verify|burn)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Extract the variable assigned from ecrecover (for the report)
# ---------------------------------------------------------------------------

_ECRECOVER_VAR_RE = re.compile(
    r"address\s+(\w+)\s*=\s*ecrecover\s*\(",
    re.IGNORECASE,
)


def _has_raw_ecrecover(body: str) -> bool:
    return bool(_ECRECOVER_RE.search(body))


def _has_null_check(body: str) -> bool:
    return bool(_NULL_CHECK_RE.search(body))


def _uses_safe_ecdsa(body: str) -> bool:
    return bool(_SAFE_ECDSA_RE.search(body))


def _is_sig_function(func: FunctionInfo) -> bool:
    return bool(_SIG_FUNC_RE.search(func.name))


def _extract_ecrecover_var(body: str) -> str:
    m = _ECRECOVER_VAR_RE.search(body)
    return m.group(1) if m else "ecrecover result"


def analyze_function_cc4(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    # Must use raw ecrecover directly in this function body
    if not _has_raw_ecrecover(func.body):
        return findings

    # Must look like a bridge / auth function
    if not _is_sig_function(func):
        return findings

    # Skip if an explicit address(0) check is already present
    if _has_null_check(func.body):
        return findings

    # Skip if OZ ECDSA.recover is also in the body — it wraps ecrecover safely
    if _uses_safe_ecdsa(func.body):
        return findings

    key_var = _extract_ecrecover_var(func.body)

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-4",
            key_var=key_var,
            guard_mapping="ecrecover",
            present_args=[],
            missing=["require(signer != address(0)) — ecrecover returns address(0) on invalid/malformed signatures"],
            severity="MEDIUM",
        )
    )

    return findings
