"""Tests for CC-9: safeTransferFrom without zero-address token guard."""
from bridge_detector.detector import analyze_source

VULN_QUBIT_PATTERN = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract QBridgeHandler {
    using SafeERC20 for IERC20;

    function deposit(address tokenAddress, uint256 amount) external {
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        _mint(msg.sender, amount);
    }

    function _mint(address, uint256) internal {}
}
interface IERC20 { function safeTransferFrom(address,address,uint256) external; }
"""

VULN_TRANSFER_FROM_PATTERN = """
pragma solidity ^0.8.0;
contract Bridge {
    function lock(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        emit Locked(msg.sender, token, amount);
    }
    event Locked(address, address, uint256);
}
interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
"""

SAFE_ZERO_CHECK_BEFORE = """
pragma solidity ^0.8.0;
contract Bridge {
    function deposit(address tokenAddress, uint256 amount) external {
        require(tokenAddress != address(0), "zero token");
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
        _mint(msg.sender, amount);
    }
    function _mint(address, uint256) internal {}
}
interface IERC20 { function safeTransferFrom(address,address,uint256) external; }
"""

SAFE_ZERO_CHECK_INVERSE = """
pragma solidity ^0.8.0;
contract Bridge {
    function deposit(address tokenAddress, uint256 amount) external {
        if (tokenAddress == address(0)) revert ZeroAddress();
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
    }
    error ZeroAddress();
}
interface IERC20 { function safeTransferFrom(address,address,uint256) external; }
"""

SAFE_HARDCODED_TOKEN = """
pragma solidity ^0.8.0;
contract Bridge {
    address public immutable TOKEN;
    constructor(address t) { TOKEN = t; }

    function deposit(uint256 amount) external {
        IERC20(TOKEN).safeTransferFrom(msg.sender, address(this), amount);
        _mint(msg.sender, amount);
    }
    function _mint(address, uint256) internal {}
}
interface IERC20 { function safeTransferFrom(address,address,uint256) external; }
"""

SAFE_NON_DEPOSIT_FUNCTION = """
pragma solidity ^0.8.0;
contract Treasury {
    function sweep(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
"""


class TestCC9Detection:

    def test_flags_qubit_pattern(self):
        findings = analyze_source(VULN_QUBIT_PATTERN, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert len(cc9) == 1
        assert cc9[0].severity == "CRITICAL"
        assert cc9[0].function_name == "deposit"

    def test_flags_transfer_from_pattern(self):
        findings = analyze_source(VULN_TRANSFER_FROM_PATTERN, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert len(cc9) == 1
        assert cc9[0].function_name == "lock"

    def test_no_flag_zero_check_before(self):
        findings = analyze_source(SAFE_ZERO_CHECK_BEFORE, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert cc9 == []

    def test_no_flag_zero_check_inverse(self):
        findings = analyze_source(SAFE_ZERO_CHECK_INVERSE, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert cc9 == []

    def test_no_flag_hardcoded_token(self):
        findings = analyze_source(SAFE_HARDCODED_TOKEN, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert cc9 == []

    def test_no_flag_non_deposit_function(self):
        findings = analyze_source(SAFE_NON_DEPOSIT_FUNCTION, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert cc9 == []

    def test_token_param_in_key_var(self):
        findings = analyze_source(VULN_QUBIT_PATTERN, "test.sol")
        cc9 = [f for f in findings if f.rule == "CC-9"]
        assert "tokenAddress" in cc9[0].key_var
