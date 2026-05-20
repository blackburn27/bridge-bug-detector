"""
CC-8 detector: Merkle proof accepted but not marked as consumed (proof replay).

The bug pattern — BNB Bridge $586M (2022), Hyperbridge (2026):
  function withdraw(bytes32[] calldata proof, bytes32 leaf) external {
      require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid proof");
      _release(recipient, amount);
      // ↑ proof is valid but never marked as used — attacker submits same proof again
  }

Merkle-proof-based bridges verify that a leaf (representing a cross-chain event)
exists in an attested root. If the proof is not invalidated after first use, it can
be replayed indefinitely to drain the bridge.

Safe patterns (suppressed):
  - A mapping write (usedProofs[x] = true) in the same function after verify()
  - processedLeaves[leaf] / claimedLeaves[leaf] pattern present
  - nullifierHashes[hash] write present (ZK-style nullifier)
  - A nonce or ID-based replay guard (not Merkle-specific but equivalent)
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Merkle proof verification call
# ---------------------------------------------------------------------------

_MERKLE_VERIFY_RE = re.compile(
    r"\bMerkleProof\s*\.\s*(verify|verifyCalldata|verifyMultiProof)\s*\(",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Bridge withdrawal / claim function names
# ---------------------------------------------------------------------------

_CLAIM_FUNC_RE = re.compile(
    r"(withdraw|claim|redeem|release|finalize|complete|execute|bridge|prove"
    r"|unlock|deliver|settle|processProof|claimWithProof)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Proof-consumed guard patterns
# ---------------------------------------------------------------------------

_PROOF_CONSUMED_RE = re.compile(
    r"\b(usedProofs|processedProofs|claimedLeaves|processedLeaves|usedLeaves"
    r"|nullifierHashes|nullifiers|spentNullifiers|proofUsed|usedRoots"
    r"|processedMessages|executedMessages|claimedMessages"
    # User-keyed claim guards: claimedTo[addr], isClaimed[x], vestings[x]
    r"|claimedTo|isClaimed|hasClaimed|isRedeemed|hasRedeemed|isExecuted"
    r"|vestingCreated|vestings|vesting)\s*\[",
    re.IGNORECASE,
)

# Generic mapping writes using a leaf/proof/nullifier/index as key
_GENERIC_PROOF_MARK_RE = re.compile(
    r"\b\w+\s*\[\s*(leaf|proofHash|nullifier|messageHash|claimId|index)\s*\]\s*=",
    re.IGNORECASE,
)

# Broader: claimed[x] = true / redeemed[x] = true patterns
_GENERIC_CLAIM_WRITE_RE = re.compile(
    r"\b(claimed|redeemed|processed|fulfilled|executed)\s*\[\s*\w+\s*\]\s*=\s*(true|false)",
    re.IGNORECASE,
)


def _has_merkle_verify(body: str) -> bool:
    return bool(_MERKLE_VERIFY_RE.search(body))


def _has_proof_consumed_guard(body: str) -> bool:
    return bool(
        _PROOF_CONSUMED_RE.search(body)
        or _GENERIC_PROOF_MARK_RE.search(body)
        or _GENERIC_CLAIM_WRITE_RE.search(body)
    )


def _is_claim_function(func: FunctionInfo) -> bool:
    return bool(_CLAIM_FUNC_RE.search(func.name))


def analyze_function_cc8(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    if not _has_merkle_verify(func.body):
        return findings

    if not _is_claim_function(func):
        return findings

    if _has_proof_consumed_guard(func.body):
        return findings

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-8",
            key_var="proof / leaf",
            guard_mapping="(none — proof not consumed)",
            present_args=[],
            missing=["usedProofs[keccak256(proof, leaf)] = true — Merkle proof never marked as used, can be replayed"],
            severity="CRITICAL",
        )
    )

    return findings
