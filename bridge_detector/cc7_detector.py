"""
CC-7 detector: msg.value vs calldata amount mismatch in native token bridge deposits.

The bug pattern — Meter Bridge $4.3M exploit (2022):
  function deposit(address token, uint256 amount) external payable {
      if (token == WETH_ADDRESS) {
          // Uses calldata `amount` instead of msg.value for the native deposit
          _creditAccount(msg.sender, amount);   // ← attacker passes amount=1_000_000 ETH, sends 0
      } else {
          IERC20(token).transferFrom(msg.sender, address(this), amount);
      }
  }

Bridge deposit functions that accept both ERC20 and native ETH (via payable) often
branch on token type. When the native-ETH branch uses the `amount` calldata parameter
instead of `msg.value`, an attacker sends 0 ETH but sets `amount` to an arbitrary
value, crediting themselves a large position on the destination chain.

Safe patterns (suppressed):
  - require(msg.value == amount) / require(msg.value >= amount) present in body
  - msg.value used directly in the credit/accounting (not `amount`)
  - No `amount` parameter at all (pure msg.value bridges are safe)
  - Function does not use msg.value at all (pure ERC20 bridge)
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# Bridge deposit / lock function names
# ---------------------------------------------------------------------------

_DEPOSIT_FUNC_RE = re.compile(
    r"(deposit|lock|bridge|send|transfer|wrap|stake|fund|supply)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# msg.value usage — indicates the function is payable and uses native ETH
# ---------------------------------------------------------------------------

_MSG_VALUE_RE = re.compile(r"\bmsg\.value\b")

# ---------------------------------------------------------------------------
# Validation: require(msg.value == amount) or require(msg.value >= amount)
# ---------------------------------------------------------------------------

_VALUE_CHECK_RE = re.compile(
    r"require\s*\([^)]*msg\.value\s*(==|>=|>)\s*\w+"
    r"|require\s*\([^)]*\w+\s*(==|<=|<)\s*msg\.value",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# Amount-like parameter names to look for
# ---------------------------------------------------------------------------

_AMOUNT_PARAM_RE = re.compile(
    r"^(amount|_amount|value|_value|amountIn|tokenAmount|depositAmount"
    r"|bridgeAmount|transferAmount|qty)$",
    re.IGNORECASE,
)


_PAYABLE_RE = re.compile(r"\bpayable\b")

# Matches a transferFrom / safeTransferFrom call including its arguments
_TRANSFER_FROM_CALL_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom)\s*\([^)]*\)",
    re.IGNORECASE,
)


def _is_payable(func: FunctionInfo) -> bool:
    """Check for payable keyword in the modifier area (between params and body)."""
    return bool(_PAYABLE_RE.search(func.modifiers))


def _has_msg_value(body: str) -> bool:
    return bool(_MSG_VALUE_RE.search(body))


def _amount_only_in_transfer(body: str, amount_param: str) -> bool:
    """
    Return True if `amount_param` appears in the body only inside
    transferFrom / safeTransferFrom argument lists — i.e. the function is
    ERC20-only and the payable keyword is incidental.
    After stripping those calls, if amount_param is still present it is used
    for native-ETH accounting (direct balance credit, _mint, etc.).
    """
    stripped = _TRANSFER_FROM_CALL_RE.sub("", body)
    return amount_param not in stripped


def _has_value_equality_check(body: str) -> bool:
    return bool(_VALUE_CHECK_RE.search(body))


def _has_amount_param(func: FunctionInfo) -> str | None:
    for name in func.params:
        if _AMOUNT_PARAM_RE.match(name):
            return name
    return None


def _is_deposit_function(func: FunctionInfo) -> bool:
    return bool(_DEPOSIT_FUNC_RE.search(func.name))


def analyze_function_cc7(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    if not _is_deposit_function(func):
        return findings

    # Must be a payable function (has payable in modifier area)
    if not _is_payable(func):
        return findings

    amount_param = _has_amount_param(func)
    if amount_param is None:
        return findings

    # Suppress if amount only appears inside transferFrom/safeTransferFrom args —
    # that means the function is purely ERC20 and the payable is incidental.
    if _amount_only_in_transfer(func.body, amount_param):
        return findings

    # Safe if there's an explicit equality/bound check
    if _has_value_equality_check(func.body):
        return findings

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-7",
            key_var=amount_param,
            guard_mapping="(none — msg.value unchecked)",
            present_args=[amount_param],
            missing=[f"require(msg.value == {amount_param}) — calldata amount not validated against actual ETH sent"],
            severity="HIGH",
        )
    )

    return findings
