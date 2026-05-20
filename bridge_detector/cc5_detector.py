"""
CC-5 detector: Missing source chain / source contract validation in bridge
message handlers.

The bug pattern:
  function executeMessage(
      address srcAddress,    // ← accepted but never validated
      uint64  srcChainId,    // ← accepted but never validated
      bytes   calldata message,
      address executor
  ) external onlyMessageBus {
      _processTransfer(message);   // any chain, any sender can trigger this
  }

A bridge message handler that receives the source-chain identifier and/or
source-contract address as parameters MUST validate them before acting on
the payload. Without this check, an attacker can:
  - Send a crafted message from an untrusted chain to trigger minting/transfers
  - Impersonate a trusted bridge contract from a different chain
  - Replay a message on the wrong destination

Real-world context:
  - Celer IM: executeMessage / sgReceive must check sender == trustedApp[srcChainId]
  - LayerZero: lzReceive must check trustedRemoteLookup[_srcChainId] == _srcAddress
  - Wormhole: bridging contracts must verify emitterAddress from VAA

Safe patterns (suppressed):
  - srcChainId / srcAddress parameter appears inside a require() condition
  - srcChainId / srcAddress parameter appears in an if(...revert/return) pattern
  - trustedRemote / trustedSource / allowedSender mapping lookup on the param
  - Parameter used in a mapping index inside a conditional expression
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Known message handler function name patterns
# ---------------------------------------------------------------------------

_MSG_HANDLER_RE = re.compile(
    r"^(executeMessage|receiveMessage|handleMessage|lzReceive|anyExecute"
    r"|onMessageReceived|processMessage|sgReceive|receivePayload"
    r"|_executeMessage|_handleMessage|_receiveMessage|deliverMessage"
    r"|validateAndExecute|onReceive|receiveWithPayload)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Source chain and source address parameter name patterns
# ---------------------------------------------------------------------------

_SRC_CHAIN_PARAM_RE = re.compile(
    r"^(srcChainId|_srcChainId|sourceChainId|_sourceChainId|fromChainId"
    r"|_fromChainId|originChainId|srcChain|_srcChain|remoteChainId|chainId"
    r"|srcEid|_srcEid|srcChainid)$",
    re.IGNORECASE,
)

_SRC_ADDR_PARAM_RE = re.compile(
    r"^(srcAddress|_srcAddress|sourceAddress|_sourceAddress|fromAddress"
    r"|_fromAddress|originAddress|remoteAddress|srcContract|_sender"
    r"|trustedSender|remoteContract|sender)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Validation detection — param appears inside require() or if(...)revert/return
# ---------------------------------------------------------------------------

def _param_is_validated(body: str, param_name: str) -> bool:
    """
    Return True if param_name appears inside a require() condition,
    an if() expression, or a mapping lookup used as a guard.
    """
    escaped = re.escape(param_name)

    # Inside require(...)
    for m in re.finditer(r"require\s*\(", body):
        paren_start = m.end() - 1
        depth = 0
        for i in range(paren_start, len(body)):
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
                if depth == 0:
                    inner = body[paren_start + 1 : i]
                    if re.search(escaped, inner):
                        return True
                    break

    # Inside if(...) — catches if (srcChainId != x) revert / return
    if re.search(rf"if\s*\([^)]*{escaped}[^)]*\)", body):
        return True

    # Mapping lookup: trustedRemotes[srcChainId] / allowedSenders[srcAddress]
    if re.search(rf"\w+\s*\[\s*{escaped}\s*\]", body):
        return True

    return False


def _find_src_params(func: FunctionInfo) -> tuple[str | None, str | None]:
    """
    Return (chain_param_name, addr_param_name) for any source chain / source
    address parameters found in the function signature. None if absent.
    """
    chain_param = None
    addr_param = None
    for name in func.params:
        if chain_param is None and _SRC_CHAIN_PARAM_RE.match(name):
            chain_param = name
        if addr_param is None and _SRC_ADDR_PARAM_RE.match(name):
            addr_param = name
    return chain_param, addr_param


def analyze_function_cc5(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    # Must be a recognised message handler function
    if not _MSG_HANDLER_RE.match(func.name):
        return findings

    chain_param, addr_param = _find_src_params(func)

    # Need at least one source identifier parameter to flag
    if chain_param is None and addr_param is None:
        return findings

    missing = []

    if chain_param and not _param_is_validated(func.body, chain_param):
        missing.append(f"source chain `{chain_param}` never validated")

    if addr_param and not _param_is_validated(func.body, addr_param):
        missing.append(f"source address `{addr_param}` never validated")

    if not missing:
        return findings

    # Build present_args as the unvalidated param names (for the report)
    unvalidated = [p for p in [chain_param, addr_param] if p is not None]

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-5",
            key_var=", ".join(unvalidated),
            guard_mapping="(none — source not bound)",
            present_args=unvalidated,
            missing=missing,
            severity="HIGH",
        )
    )

    return findings
