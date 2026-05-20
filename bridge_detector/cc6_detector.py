"""
CC-6 detector: Unvalidated external call with user-supplied calldata (calldata injection).

The bug pattern — Socket Protocol $3.3M exploit (Jan 2024):
  function bridgeViaRoute(address target, bytes calldata routeData) external payable {
      (bool success,) = target.call{value: msg.value}(routeData);
      // ↑ target and routeData are user-controlled — no allowlist check
  }

Bridge routers aggregate DEX/bridge routes and accept opaque calldata to forward.
Users grant large (often infinite) ERC20 approvals to these routers. Without
validating that `target` is a whitelisted contract, an attacker can pass:
  target  = USDC_CONTRACT
  payload = transferFrom(victim, attacker, MAX_UINT)
...draining every user who approved the router.

Safe patterns (suppressed):
  - require(allowedTargets[target]) / require(whitelistedRouters[target]) before the call
  - require(isApproved[target]) / require(approvedRouters[target])
  - if (!allowedContracts[target]) revert
  - target is msg.sender or address(this) (not user-supplied)
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Low-level external call patterns
# ---------------------------------------------------------------------------

# .call( / .call{value:...}( / .delegatecall(
_EXTERNAL_CALL_RE = re.compile(
    r"\.\s*(call|delegatecall)\s*(\{[^}]*\})?\s*\(",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Allowlist / whitelist guard patterns — any of these suppress the finding
# ---------------------------------------------------------------------------

_ALLOWLIST_RE = re.compile(
    r"\b(allowedTargets|whitelistedRouters|allowedRouters|approvedRouters"
    r"|allowedContracts|approvedContracts|allowedCallers|whitelistedTargets"
    r"|validTargets|trustedTargets|approvedTargets|isWhitelisted|isApproved"
    r"|isAllowed|isValidTarget|routerAllowlist|allowlist)\s*\[",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Bridge router / aggregator function names
# ---------------------------------------------------------------------------

_ROUTER_FUNC_RE = re.compile(
    r"(bridge|swap|route|relay|execute|forward|dispatch|perform|aggregate"
    r"|transfer|send|callTo|callAny|multiCall|batchCall)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Detect if the call target is a user-supplied parameter
# (as opposed to a hardcoded state variable like lzEndpoint)
# ---------------------------------------------------------------------------

_USER_TARGET_CALL_RE = re.compile(
    r"(\w+)\s*\.\s*(call|delegatecall)\s*(\{[^}]*\})?\s*\(",
    re.IGNORECASE,
)


def _has_external_call(body: str) -> bool:
    return bool(_EXTERNAL_CALL_RE.search(body))


def _has_allowlist_check(body: str) -> bool:
    return bool(_ALLOWLIST_RE.search(body))


def _is_router_function(func: FunctionInfo) -> bool:
    return bool(_ROUTER_FUNC_RE.search(func.name))


def _call_target_is_param(body: str, params: list[str]) -> bool:
    """
    Return True if the target of a .call() is one of the function parameters,
    meaning it is user-supplied rather than a hardcoded contract reference.
    """
    for m in _USER_TARGET_CALL_RE.finditer(body):
        target_var = m.group(1)
        if target_var in params:
            return True
    return False


def analyze_function_cc6(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    if not _has_external_call(func.body):
        return findings

    if not _is_router_function(func):
        return findings

    # Safe if an allowlist mapping is checked before the call
    if _has_allowlist_check(func.body):
        return findings

    # Only flag if the call target is actually user-supplied
    if not _call_target_is_param(func.body, func.params):
        return findings

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-6",
            key_var="target",
            guard_mapping="(none — no allowlist)",
            present_args=func.params,
            missing=["require(allowedTargets[target]) — user-supplied call target not allowlisted"],
            severity="CRITICAL",
        )
    )

    return findings
