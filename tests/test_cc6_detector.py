"""Tests for CC-6: Unvalidated external call with user-supplied calldata."""
from bridge_detector.detector import analyze_source

VULN_SOCKET_PATTERN = """
pragma solidity ^0.8.0;
contract BridgeRouter {
    function bridgeViaRoute(address target, bytes calldata routeData, uint256 amount) external payable {
        (bool success,) = target.call{value: msg.value}(routeData);
        require(success, "call failed");
    }
}
"""

VULN_EXECUTE_PATTERN = """
pragma solidity ^0.8.0;
contract Bridge {
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
    }
}
"""

SAFE_ALLOWLIST_CHECK = """
pragma solidity ^0.8.0;
contract BridgeRouter {
    mapping(address => bool) public allowedTargets;
    function bridgeViaRoute(address target, bytes calldata routeData) external payable {
        require(allowedTargets[target], "target not whitelisted");
        (bool success,) = target.call{value: msg.value}(routeData);
        require(success, "call failed");
    }
}
"""

SAFE_NON_BRIDGE_FUNCTION = """
pragma solidity ^0.8.0;
contract Admin {
    function adminCall(address target, bytes calldata data) external onlyOwner {
        (bool ok,) = target.call(data);
    }
    modifier onlyOwner() { _; }
}
"""

SAFE_HARDCODED_TARGET = """
pragma solidity ^0.8.0;
contract Bridge {
    address public immutable endpoint;
    function send(bytes calldata payload) external {
        (bool ok,) = endpoint.call(payload);
        require(ok);
    }
}
"""

SAFE_WHITELISTED_ROUTERS = """
pragma solidity ^0.8.0;
contract BridgeRouter {
    mapping(address => bool) public whitelistedRouters;
    function relay(address target, bytes calldata data) external {
        require(whitelistedRouters[target], "not approved");
        (bool ok,) = target.call(data);
    }
}
"""


class TestCC6Detection:

    def test_flags_socket_pattern(self):
        findings = analyze_source(VULN_SOCKET_PATTERN, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert len(cc6) == 1
        assert cc6[0].severity == "CRITICAL"
        assert cc6[0].function_name == "bridgeViaRoute"

    def test_flags_execute_pattern(self):
        findings = analyze_source(VULN_EXECUTE_PATTERN, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert len(cc6) == 1
        assert cc6[0].function_name == "execute"

    def test_no_flag_with_allowlist(self):
        findings = analyze_source(SAFE_ALLOWLIST_CHECK, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert cc6 == []

    def test_no_flag_non_bridge_function(self):
        findings = analyze_source(SAFE_NON_BRIDGE_FUNCTION, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert cc6 == []

    def test_no_flag_hardcoded_target(self):
        findings = analyze_source(SAFE_HARDCODED_TARGET, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert cc6 == []

    def test_no_flag_whitelisted_routers(self):
        findings = analyze_source(SAFE_WHITELISTED_ROUTERS, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert cc6 == []

    def test_severity_is_critical(self):
        findings = analyze_source(VULN_SOCKET_PATTERN, "test.sol")
        cc6 = [f for f in findings if f.rule == "CC-6"]
        assert cc6[0].severity == "CRITICAL"
