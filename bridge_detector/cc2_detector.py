"""
CC-2 detector: Missing source-tx idempotency guard.

The Adshares bug pattern:
  function wrapTo(address account, uint256 amount, uint64 from, uint64 txid) {
      emit Wrap(account, from, txid, amount);   // txid only logged
      _mint(account, amount);                   // tokens minted
      // NO: require(!usedTxids[txid]);
      // NO: usedTxids[txid] = true;
  }

A bridge mint function that accepts a source-chain tx identifier as a parameter
but never stores it in a mapping — meaning the same txid can be replayed
indefinitely to mint unlimited tokens.
"""

import re

from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Parameter name patterns — anything that looks like a source-chain tx ref
# ---------------------------------------------------------------------------

_TX_ID_PARAM_RE = re.compile(
    r"^_?(txid|txhash|msghash|messageid|msgid|transferid|depositid|"
    r"refid|nonce|msgnonce|messagenonce|sequence|eventnonce|"
    r"srctxhash|sourcetxhash|sourcetxid|bridgeid|requestid|"
    r"payloadhash|packetid|packetseq|msgseq)$",
    re.IGNORECASE,
)

# Types that are used for tx identifiers (exclude address, bool, etc.)
_TX_ID_TYPES_RE = re.compile(
    r"^(bytes32|bytes|uint64|uint128|uint256|uint)$",
    re.IGNORECASE,
)

# Minting operations — covers _mint(), .mint(), mintTo()
_MINT_RE = re.compile(
    r"\b(_mint|mintTo|_mintTo)\s*\(|(?<![_\w])mint\s*\(",
)

# Bridge/fulfillment function name hints — no trailing \b so wrapTo, fulfillBridge etc. match
_BRIDGE_FUNC_RE = re.compile(
    r"(wrap|fulfill|relay|execute|claim|redeem|complete|finalize|"
    r"deliver|process|handle|receive|bridge)",
    re.IGNORECASE,
)

# Trusted-caller check inside function body: require(msg.sender == address(X)) / == X
# Indicates replay protection is delegated to the calling contract (e.g. LZ endpoint)
_TRUSTED_CALLER_BODY_RE = re.compile(
    r"require\s*\(\s*msg\.sender\s*==\s*(?:address\s*\()?\w+",
)

# Trusted-caller modifiers in the function signature area (onlyEndpoint, onlyGateway, etc.)
_TRUSTED_CALLER_MOD_RE = re.compile(
    r"\b(onlyEndpoint|onlyGateway|onlyBridge|onlyRouter|onlyRelayer|"
    r"onlyOracle|onlyExecutor|onlyMessenger|onlySource)\b",
    re.IGNORECASE,
)


def _is_bridge_mint_function(func: FunctionInfo) -> bool:
    return bool(_BRIDGE_FUNC_RE.search(func.name))


def _has_trusted_caller_guard(func: FunctionInfo) -> bool:
    """
    Return True if the function restricts callers to a single trusted address.
    These architectures delegate replay protection to the caller (e.g. LayerZero
    endpoint, Axelar gateway) rather than storing a txid mapping themselves.
    Finding is still emitted but downgraded to INFORMATIONAL.
    """
    return bool(
        _TRUSTED_CALLER_BODY_RE.search(func.body)
        or _TRUSTED_CALLER_MOD_RE.search(func.body)
    )


def _has_mint_op(body: str) -> bool:
    return bool(_MINT_RE.search(body))


def _find_tx_identifier_params(func: FunctionInfo) -> list[tuple[str, str]]:
    """
    Return (type, name) pairs from the function's parameters that look like
    source-chain transaction identifiers.
    """
    matches = []
    for type_, name in func.typed_params:
        if _TX_ID_PARAM_RE.match(name) and _TX_ID_TYPES_RE.match(type_):
            matches.append((type_, name))
    return matches


def _keccak_contents(body: str) -> list[str]:
    """
    Return the inner content of every keccak256(...) call in body,
    using proper paren matching so nested calls are handled correctly.
    """
    results = []
    search_from = 0
    while True:
        idx = body.find("keccak256", search_from)
        if idx == -1:
            break
        paren_start = body.find("(", idx)
        if paren_start == -1:
            break
        depth = 0
        for i in range(paren_start, len(body)):
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
                if depth == 0:
                    results.append(body[paren_start + 1 : i])
                    break
        search_from = paren_start + 1
    return results


def _param_has_replay_guard(body: str, param_name: str) -> bool:
    """
    Return True if param_name is protected by a replay guard in body.

    Covers three patterns:
      1. Direct:   mapping[param] checked or written
      2. Inline:   mapping[keccak256(...param...)] checked or written
      3. Indirect: key = keccak256(...param...); mapping[key] written
    """
    esc = re.escape(param_name)

    # Pattern 1 & 2: param appears literally inside [...]
    if re.search(rf"\[[^\]]*\b{esc}\b[^\]]*\]", body):
        return True

    # Pattern 3: param appears inside an actual keccak256 call's arguments
    # AND there's at least one mapping-write in the function
    for keccak_inner in _keccak_contents(body):
        if re.search(rf"\b{esc}\b", keccak_inner):
            has_mapping_write = re.search(r"\b\w+\[[^\]]+\]\s*=\s*(?:true\b|[^=])", body)
            if has_mapping_write:
                return True

    return False


def analyze_function_cc2(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    if not _is_bridge_mint_function(func):
        return findings

    if not _has_mint_op(func.body):
        return findings

    tx_params = _find_tx_identifier_params(func)
    if not tx_params:
        return findings

    trusted_caller = _has_trusted_caller_guard(func)

    for param_type, param_name in tx_params:
        if _param_has_replay_guard(func.body, param_name):
            continue  # this identifier is guarded — safe

        if trusted_caller:
            # Replay protection delegated to the caller (e.g. LZ endpoint).
            # Still emit as INFORMATIONAL so it shows up in audit trails.
            severity = "INFORMATIONAL"
            missing = [
                f"contract-level mapping for {param_name} "
                f"(currently relies on trusted caller for replay protection)"
            ]
        else:
            severity = "HIGH"
            missing = [f"mapping storing {param_name} to prevent replay"]

        findings.append(
            Finding(
                file_path=file_path,
                function_name=func.name,
                line=func.start_line,
                rule="CC-2",
                key_var=param_name,
                guard_mapping="(none — missing)" if not trusted_caller else "(delegated to caller)",
                present_args=[f"{param_type} {param_name}"],
                missing=missing,
                severity=severity,
            )
        )

    return findings
