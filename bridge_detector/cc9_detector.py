"""
CC-9 detector: safeTransferFrom called with user-supplied token address, no
               address(0) guard — null-address deposit bypass.

The bug pattern — Qubit Finance $80M exploit (2022):
  function deposit(address tokenAddress, uint256 amount) external {
      // If tokenAddress == address(0), safeTransferFrom targets a non-contract
      // (zero address is an EOA), returns empty bytes, and OZ's safeTransferFrom
      // interprets the empty return as success.
      IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
      _mint(msg.sender, amount);   // ← tokens minted with nothing received
  }

When `tokenAddress` is address(0), the call to `IERC20(address(0)).safeTransferFrom`
targets the zero address. Since the zero address is an EOA (no code), the low-level
call returns success with empty returndata. OZ's SafeERC20 interprets an empty
return as a successful transfer (pre-ERC20 tokens don't return bool). The bridge
credits the caller without receiving any actual tokens.

Safe patterns (suppressed):
  - require(tokenAddress != address(0)) / require(token != address(0)) before transfer
  - if (tokenAddress == address(0)) revert / return
  - address(0) / ZERO_ADDRESS comparison anywhere before the safeTransferFrom call
  - transferFrom on a hardcoded token address (not a parameter)
"""

import re
from .parser import FunctionInfo
from .detector import Finding


# ---------------------------------------------------------------------------
# safeTransferFrom / transferFrom call
# ---------------------------------------------------------------------------

_SAFE_TRANSFER_RE = re.compile(
    r"\b(safeTransferFrom|transferFrom)\s*\(",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Zero-address guard patterns
# ---------------------------------------------------------------------------

_ZERO_ADDR_GUARD_RE = re.compile(
    r"!=\s*address\s*\(\s*0\s*\)"          # != address(0)
    r"|==\s*address\s*\(\s*0\s*\)"         # == address(0) [revert branch]
    r"|address\s*\(\s*0\s*\)\s*!="         # address(0) != token
    r"|address\s*\(\s*0\s*\)\s*=="
    r"|\bZERO_ADDRESS\b"
    r"|\baddress\s*\(\s*0\s*\)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Bridge deposit / lock function names
# ---------------------------------------------------------------------------

_DEPOSIT_FUNC_RE = re.compile(
    r"(deposit|lock|bridge|send|transfer|wrap|stake|fund|supply|addLiquidity)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Token-like parameter names
# ---------------------------------------------------------------------------

_TOKEN_PARAM_RE = re.compile(
    r"^(token|tokenAddress|tokenAddr|_token|_tokenAddress|asset|_asset"
    r"|erc20|erc20Address|coin|coinAddress)$",
    re.IGNORECASE,
)


def _has_safe_transfer(body: str) -> bool:
    return bool(_SAFE_TRANSFER_RE.search(body))


def _has_zero_addr_guard(body: str) -> bool:
    return bool(_ZERO_ADDR_GUARD_RE.search(body))


def _is_deposit_function(func: FunctionInfo) -> bool:
    return bool(_DEPOSIT_FUNC_RE.search(func.name))


def _token_param_is_user_supplied(func: FunctionInfo) -> str | None:
    for name in func.params:
        if _TOKEN_PARAM_RE.match(name):
            return name
    return None


def analyze_function_cc9(func: FunctionInfo, file_path: str) -> list[Finding]:
    findings = []

    if not _is_deposit_function(func):
        return findings

    if not _has_safe_transfer(func.body):
        return findings

    token_param = _token_param_is_user_supplied(func)
    if token_param is None:
        return findings

    if _has_zero_addr_guard(func.body):
        return findings

    findings.append(
        Finding(
            file_path=file_path,
            function_name=func.name,
            line=func.start_line,
            rule="CC-9",
            key_var=token_param,
            guard_mapping="(none — zero address unchecked)",
            present_args=[token_param],
            missing=[f"require({token_param} != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens"],
            severity="CRITICAL",
        )
    )

    return findings
