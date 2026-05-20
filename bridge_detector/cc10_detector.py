"""
CC-10 detector: Privileged mint/release with single trusted role and no threshold
                signature verification (single point of failure).

The bug pattern — Ronin $624M (2022), Harmony $100M, Multichain $130M (2023):
  function fulfillMint(address recipient, uint256 amount) external onlyRelayer {
      // Single key compromise = unlimited minting
      // No cryptographic proof of source-chain burn
      // No M-of-N signature threshold
      IToken(token).mint(recipient, amount);
  }

The mint/release function on a bridge is the highest-value target. Guarding it
with a single `onlyOwner`/`onlyRelayer` modifier (backed by one private key) means
that a single key compromise results in unlimited token printing. Safe bridges
require an M-of-N threshold of validator signatures over the mint parameters before
executing.

Safe patterns (suppressed):
  - Function has a `bytes[]` / `bytes[] calldata signatures` parameter (threshold sigs)
  - Function body contains signature array iteration or threshold count check
  - Function uses MPC / multi-sig patterns (signatureCount, quorum, threshold)
  - Function calls an internal _verifySignatures / _checkThreshold helper
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Mint / release function name patterns
# ---------------------------------------------------------------------------

_MINT_FUNC_RE = re.compile(
    r"(fulfill|mint|release|unlock|redeem|claim|deliver|finalize|complete|execute)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Single-role access control modifiers (no threshold)
# ---------------------------------------------------------------------------

_SINGLE_ROLE_RE = re.compile(
    r"\b(onlyOwner|onlyRelayer|onlyValidator|onlyOperator|onlyBridge"
    r"|onlyMinter|onlyAdmin|onlyGovernor|onlyExecutor|onlyTrusted"
    r"|onlyRole\s*\(\s*\w+\s*\))\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Threshold / multi-sig patterns — any of these suppress the finding
# ---------------------------------------------------------------------------

# Signature array parameter
_SIG_ARRAY_PARAM_RE = re.compile(
    r"bytes\s*\[\s*\]\s*(calldata|memory)?\s+\w*(sig|signature|sigs|signatures)\w*",
    re.IGNORECASE,
)

# Threshold/quorum variables or function calls in body
_THRESHOLD_BODY_RE = re.compile(
    r"\b(threshold|quorum|minSignatures|signatureCount|_signatures|signatures\s*\."
    r"|_verifySignatures|checkSignatures|verifyThreshold|_checkThreshold"
    r"|requiredSignatures|numSignatures|sigCount)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Token mint call in body
# ---------------------------------------------------------------------------

_MINT_CALL_RE = re.compile(
    r"\.\s*mint\s*\(|\b_mint\s*\(",
    re.IGNORECASE,
)


def _is_mint_function(func: FunctionInfo) -> bool:
    return bool(_MINT_FUNC_RE.search(func.name))


def _has_single_role_guard(func: FunctionInfo) -> bool:
    # Modifiers are in the function declaration area, not the body
    return bool(_SINGLE_ROLE_RE.search(func.modifiers))


def _has_threshold_pattern(func: FunctionInfo) -> bool:
    # Signature array in params
    param_str = " ".join(func.params)
    # Check typed params for bytes[] signatures
    for type_, name in func.typed_params:
        if re.search(r"bytes\s*\[\s*\]", type_) and re.search(r"sig", name, re.IGNORECASE):
            return True
    # Check body for threshold logic
    return bool(_THRESHOLD_BODY_RE.search(func.body))


def _has_mint_call(body: str) -> bool:
    return bool(_MINT_CALL_RE.search(body))


def analyze_function_cc10(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    if not _is_mint_function(func):
        return findings

    # Must actually call mint (not just be named "fulfillMint" without minting)
    if not _has_mint_call(func.body):
        return findings

    # Must have a single-role guard — indicates access control IS attempted
    # (functions with no access control are a different, more obvious issue)
    if not _has_single_role_guard(func):
        return findings

    # Safe if threshold multi-sig is present
    if _has_threshold_pattern(func):
        return findings

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-10",
            key_var="onlyRelayer/onlyOwner",
            guard_mapping="single-key role",
            present_args=[],
            missing=["M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)"],
            severity="HIGH",
        )
    )

    return findings
