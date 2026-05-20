"""Tests for CC-7: msg.value vs calldata amount mismatch."""
from bridge_detector.detector import analyze_source

VULN_METER_PATTERN = """
pragma solidity ^0.8.0;
contract Bridge {
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    mapping(address => uint256) public balances;

    function deposit(address token, uint256 amount) external payable {
        if (token == WETH) {
            balances[msg.sender] += amount;
        } else {
            IERC20(token).transferFrom(msg.sender, address(this), amount);
            balances[msg.sender] += amount;
        }
    }
}
interface IERC20 { function transferFrom(address,address,uint256) external; }
"""

VULN_WRAP_PATTERN = """
pragma solidity ^0.8.0;
contract NativeWrapper {
    function wrap(uint256 amount) external payable {
        _mint(msg.sender, amount);
    }
    function _mint(address, uint256) internal {}
}
"""

SAFE_REQUIRE_EQUALITY = """
pragma solidity ^0.8.0;
contract Bridge {
    function deposit(address token, uint256 amount) external payable {
        if (token == address(0)) {
            require(msg.value == amount, "value mismatch");
            _credit(msg.sender, amount);
        }
    }
    function _credit(address, uint256) internal {}
}
"""

SAFE_REQUIRE_GTE = """
pragma solidity ^0.8.0;
contract Bridge {
    function deposit(uint256 amount) external payable {
        require(msg.value >= amount, "insufficient value");
        _credit(msg.sender, amount);
    }
    function _credit(address, uint256) internal {}
}
"""

SAFE_NO_AMOUNT_PARAM = """
pragma solidity ^0.8.0;
contract Bridge {
    function depositNative() external payable {
        _credit(msg.sender, msg.value);
    }
    function _credit(address, uint256) internal {}
}
"""

SAFE_NO_MSG_VALUE = """
pragma solidity ^0.8.0;
contract Bridge {
    function deposit(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, address(this), amount);
    }
}
interface IERC20 { function transferFrom(address,address,uint256) external; }
"""


class TestCC7Detection:

    def test_flags_meter_pattern(self):
        findings = analyze_source(VULN_METER_PATTERN, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert len(cc7) == 1
        assert cc7[0].severity == "HIGH"
        assert cc7[0].function_name == "deposit"

    def test_flags_wrap_pattern(self):
        findings = analyze_source(VULN_WRAP_PATTERN, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert len(cc7) == 1
        assert cc7[0].function_name == "wrap"

    def test_no_flag_require_equality(self):
        findings = analyze_source(SAFE_REQUIRE_EQUALITY, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert cc7 == []

    def test_no_flag_require_gte(self):
        findings = analyze_source(SAFE_REQUIRE_GTE, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert cc7 == []

    def test_no_flag_no_amount_param(self):
        findings = analyze_source(SAFE_NO_AMOUNT_PARAM, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert cc7 == []

    def test_no_flag_no_msg_value(self):
        findings = analyze_source(SAFE_NO_MSG_VALUE, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert cc7 == []

    def test_key_var_is_amount(self):
        findings = analyze_source(VULN_METER_PATTERN, "test.sol")
        cc7 = [f for f in findings if f.rule == "CC-7"]
        assert cc7[0].key_var == "amount"
