"""
CC-3 detector: Missing chain ID in off-chain signature digest.

The bug pattern:
  function mint(address to, uint256 amount, uint256 nonce, bytes calldata sig) {
      bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));
      require(ECDSA.recover(hash, sig) == trustedSigner);   // ← no chainId in hash
      _mint(to, amount);
  }

If block.chainid is absent from the signed message, a signature produced for
Chain A is cryptographically valid on Chain B (assuming the same contract
address). An attacker can collect one valid signature and replay it across
every chain where the contract is deployed.

Safe patterns (skipped):
  - Contract inherits OZ EIP712 (chainId baked into domain separator)
  - DOMAIN_SEPARATOR / domainSeparator() used in the hash
  - block.chainid / chainId present in the encodePacked arguments
  - require(chainId == block.chainid) guard in the function body
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Signature verification calls
# ---------------------------------------------------------------------------

# ecrecover(hash, v, r, s) — raw precompile
_ECRECOVER_RE = re.compile(r"\becrecover\s*\(")

# ECDSA.recover(hash, sig) / ECDSA.tryRecover / hash.recover(sig) via using-for
_ECDSA_RE = re.compile(
    r"\b(ECDSA\.recover|ECDSA\.tryRecover|SignatureChecker\.isValidSignatureNow"
    r"|MessageHashUtils\.toEthSignedMessageHash)\s*\("
    r"|\.recover\s*\(\s*\w+\s*\)",  # hash.recover(sig) — using ECDSA for bytes32
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Safe patterns — if present, skip (chainId already handled)
# ---------------------------------------------------------------------------

# EIP-712 domain separator usage in the function
_DOMAIN_SEP_RE = re.compile(
    r"\b(DOMAIN_SEPARATOR|domainSeparator|_domainSeparatorV4|_hashTypedDataV4"
    r"|EIP712|eip712|DOMAIN_TYPEHASH)\b",
    re.IGNORECASE,
)

# block.chainid or a chainId / chain_id / networkId / blockchainId variable in the hash arguments.
# Custom deployment-time constants like blockchainId, networkId, fxBridgeId are accepted as
# chain-binding equivalents — they're set per deployment and serve the same purpose.
_CHAIN_ID_RE = re.compile(
    r"\b(block\.chainid|chainId|chain_id|chainid|getChainId"
    r"|blockchainId|networkId|_networkId|fxBridgeId|_fxBridgeId|bridgeId|_bridgeId)\b",
    re.IGNORECASE,
)

# Explicit chain check: require(chainId == block.chainid) or similar
_CHAIN_CHECK_RE = re.compile(
    r"require\s*\(.*?chain.*?==.*?block\.chainid|block\.chainid.*?==.*?chain",
    re.IGNORECASE | re.DOTALL,
)

# Contract-level EIP712 inheritance marker (appears in class body, not function)
_EIP712_INHERIT_RE = re.compile(r"\bEIP712\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Bridge/auth function hints — functions likely to verify signatures
# ---------------------------------------------------------------------------

_SIG_FUNC_RE = re.compile(
    r"(mint|claim|redeem|fulfill|relay|execute|bridge|withdraw|wrap"
    r"|transfer|deliver|process|receive|finalize|complete|unlock|submit|verify|burn)",
    re.IGNORECASE,
)

# Calls to internal sig-verification helpers: recoverSigner, _recover, verifySig, checkSig, etc.
_SIG_HELPER_RE = re.compile(
    r"\b(recoverSigner|_recoverSigner|recoverAddress|getSigner|_getSigner"
    r"|verifySig|_verifySig|checkSignature|_checkSignature|verifySignature"
    r"|checkSig|_checkSig|_verify|verifyAndRecover)\s*\(",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# encodePacked hash construction (the vulnerable form)
# ---------------------------------------------------------------------------

_ENCODE_PACKED_RE = re.compile(
    r"keccak256\s*\(\s*abi\.encodePacked\s*\(",
    re.DOTALL,
)

# abi.encode (EIP-712 typed data) — usually safe if domain sep used
_ENCODE_TYPED_RE = re.compile(
    r"keccak256\s*\(\s*abi\.encode\s*\(",
    re.DOTALL,
)


def _has_sig_verification(body: str) -> bool:
    return bool(
        _ECRECOVER_RE.search(body)
        or _ECDSA_RE.search(body)
        or _SIG_HELPER_RE.search(body)
    )


def _has_safe_domain_sep(body: str) -> bool:
    return bool(_DOMAIN_SEP_RE.search(body))


def _has_chain_id_in_body(body: str) -> bool:
    return bool(_CHAIN_ID_RE.search(body))


def _has_chain_check(body: str) -> bool:
    return bool(_CHAIN_CHECK_RE.search(body))


def _has_vulnerable_encode_packed(body: str) -> bool:
    """
    Return True if the function constructs a keccak256(abi.encodePacked(...))
    hash — the hand-rolled form that is likely missing chainId.
    abi.encode() is used for EIP-712 typed hashes and is usually safe.
    """
    return bool(_ENCODE_PACKED_RE.search(body))


def _is_sig_function(func: FunctionInfo) -> bool:
    return bool(_SIG_FUNC_RE.search(func.name))


def _extract_packed_args(body: str) -> list[str]:
    """
    Extract args from the first keccak256(abi.encodePacked(...)) call.
    Uses depth-tracking to handle nested calls.
    """
    idx = body.find("keccak256")
    while idx != -1:
        paren_start = body.find("(", idx)
        if paren_start == -1:
            break
        # find abi.encodePacked inside
        ep_idx = body.find("abi.encodePacked", paren_start)
        if ep_idx == -1 or ep_idx > paren_start + 200:
            idx = body.find("keccak256", idx + 1)
            continue
        ep_paren = body.find("(", ep_idx)
        if ep_paren == -1:
            break
        depth = 0
        for i in range(ep_paren, len(body)):
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
                if depth == 0:
                    inner = body[ep_paren + 1 : i]
                    # Split by commas at depth 0
                    args, current, d = [], [], 0
                    for ch in inner:
                        if ch == "(":
                            d += 1
                        elif ch == ")":
                            d -= 1
                        if ch == "," and d == 0:
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
        idx = body.find("keccak256", idx + 1)
    return []


def analyze_function_cc3(func: FunctionInfo, file_path: str, source: str = "") -> list[Finding]:
    findings = []

    # Must have a signature verification call
    if not _has_sig_verification(func.body):
        return findings

    # Must look like a bridge/auth function
    if not _is_sig_function(func):
        return findings

    # Skip if EIP-712 domain separator is used — chainId is in the domain
    if _has_safe_domain_sep(func.body):
        return findings

    # Skip if contract-level EIP712 inheritance detected in full source
    if source and _EIP712_INHERIT_RE.search(source):
        return findings

    # Skip if there's an explicit chain ID check
    if _has_chain_check(func.body):
        return findings

    # Must use hand-rolled abi.encodePacked (not EIP-712 typed data)
    if not _has_vulnerable_encode_packed(func.body):
        return findings

    # If chainId appears anywhere in the body, it's likely in the hash — safe
    if _has_chain_id_in_body(func.body):
        return findings

    # Extract what IS in the packed hash for the report
    present_args = _extract_packed_args(func.body)

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-3",
            key_var="hash",
            guard_mapping="ECDSA.recover / ecrecover",
            present_args=present_args if present_args else ["(could not extract)"],
            missing=["block.chainid in signed message digest"],
            severity="HIGH",
        )
    )

    return findings
