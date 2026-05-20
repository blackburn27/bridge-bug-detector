"""
Tests for CC-5 detector: Missing source chain/address validation in message handlers.
"""

from bridge_detector.detector import analyze_source


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Vulnerable: Celer IM pattern — srcAddress and srcChainId never validated
VULN_CELER_EXECUTE_MESSAGE = """
pragma solidity ^0.8.0;

contract BridgeApp {
    function executeMessage(
        address srcAddress,
        uint64 srcChainId,
        bytes calldata message,
        address executor
    ) external returns (bool) {
        _processTransfer(message);
        return true;
    }

    function _processTransfer(bytes calldata message) internal {}
}
"""

# Vulnerable: LayerZero lzReceive — _srcChainId and _srcAddress not validated
VULN_LZ_RECEIVE = """
pragma solidity ^0.8.0;

contract OmniToken {
    address public lzEndpoint;

    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 _nonce,
        bytes calldata _payload
    ) external {
        require(msg.sender == lzEndpoint, "not endpoint");
        (address to, uint256 amount) = abi.decode(_payload, (address, uint256));
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Vulnerable: only srcChainId validated, srcAddress is not
VULN_ONLY_CHAIN_VALIDATED = """
pragma solidity ^0.8.0;

contract Bridge {
    uint64 public constant HOME_CHAIN = 1;

    function executeMessage(
        address srcAddress,
        uint64 srcChainId,
        bytes calldata message
    ) external {
        require(srcChainId == HOME_CHAIN, "wrong chain");
        // srcAddress never checked — any contract on HOME_CHAIN can call this
        _execute(message);
    }

    function _execute(bytes calldata message) internal {}
}
"""

# Vulnerable: only srcAddress validated, srcChainId is not
VULN_ONLY_ADDR_VALIDATED = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedApp;

    function executeMessage(
        address srcAddress,
        uint64 srcChainId,
        bytes calldata message
    ) external {
        require(srcAddress == trustedApp, "wrong sender");
        // srcChainId never checked — trustedApp on any chain accepted
        _execute(message);
    }

    function _execute(bytes calldata message) internal {}
}
"""

# Safe: both srcChainId and srcAddress validated in require()
SAFE_BOTH_VALIDATED = """
pragma solidity ^0.8.0;

contract Bridge {
    uint64 public constant HOME_CHAIN = 1;
    address public trustedApp;

    function executeMessage(
        address srcAddress,
        uint64 srcChainId,
        bytes calldata message
    ) external {
        require(srcChainId == HOME_CHAIN, "wrong source chain");
        require(srcAddress == trustedApp, "wrong source contract");
        _execute(message);
    }

    function _execute(bytes calldata message) internal {}
}
"""

# Safe: LayerZero trustedRemote mapping lookup validates both
SAFE_TRUSTED_REMOTE_MAPPING = """
pragma solidity ^0.8.0;

contract LzApp {
    mapping(uint16 => bytes) public trustedRemoteLookup;

    function lzReceive(
        uint16 _srcChainId,
        bytes calldata _srcAddress,
        uint64 _nonce,
        bytes calldata _payload
    ) external {
        bytes memory trustedRemote = trustedRemoteLookup[_srcChainId];
        require(
            trustedRemote.length != 0 &&
            keccak256(_srcAddress) == keccak256(trustedRemote),
            "LzApp: invalid source"
        );
        _blockingLzReceive(_srcChainId, _srcAddress, _nonce, _payload);
    }

    function _blockingLzReceive(uint16, bytes calldata, uint64, bytes calldata) internal {}
}
"""

# Safe: not a recognised message handler function name
SAFE_NOT_A_HANDLER = """
pragma solidity ^0.8.0;

contract Bridge {
    function bridgeTokens(
        address srcAddress,
        uint64 srcChainId,
        uint256 amount
    ) external {
        // Not a message handler — CC-5 should not fire
        _transfer(srcAddress, amount);
    }

    function _transfer(address to, uint256 amount) internal {}
}
"""

# Safe: sgReceive with mapping guard
SAFE_SG_RECEIVE_MAPPING = """
pragma solidity ^0.8.0;

contract StargateBridge {
    mapping(uint16 => mapping(bytes => bool)) public trustedSources;

    function sgReceive(
        uint16 _srcChainId,
        bytes memory _srcAddress,
        uint256 _nonce,
        address _token,
        uint256 amountLD,
        bytes memory payload
    ) external {
        require(trustedSources[_srcChainId][_srcAddress], "untrusted source");
        _process(_token, amountLD, payload);
    }

    function _process(address, uint256, bytes memory) internal {}
}
"""

# Vulnerable: receiveMessage with unvalidated _sender
VULN_RECEIVE_MESSAGE_SENDER = """
pragma solidity ^0.8.0;

contract Bridge {
    function receiveMessage(
        address _sender,
        uint256 srcChainId,
        bytes calldata data
    ) external {
        _processData(data);
    }

    function _processData(bytes calldata data) internal {}
}
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCC5Detection:

    def test_flags_celer_execute_message(self):
        findings = analyze_source(VULN_CELER_EXECUTE_MESSAGE, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert len(cc5) == 1
        assert cc5[0].severity == "HIGH"
        assert cc5[0].function_name == "executeMessage"

    def test_flags_both_params_missing(self):
        findings = analyze_source(VULN_CELER_EXECUTE_MESSAGE, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        missing_text = " ".join(cc5[0].missing)
        assert "srcChainId" in missing_text
        assert "srcAddress" in missing_text

    def test_flags_lz_receive_unvalidated(self):
        findings = analyze_source(VULN_LZ_RECEIVE, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert len(cc5) == 1
        assert cc5[0].function_name == "lzReceive"

    def test_flags_when_only_chain_validated(self):
        """srcAddress still unvalidated — should flag with just the address missing."""
        findings = analyze_source(VULN_ONLY_CHAIN_VALIDATED, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert len(cc5) == 1
        missing_text = " ".join(cc5[0].missing)
        assert "srcAddress" in missing_text
        assert "srcChainId" not in missing_text

    def test_flags_when_only_addr_validated(self):
        """srcChainId still unvalidated — should flag with just the chain missing."""
        findings = analyze_source(VULN_ONLY_ADDR_VALIDATED, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert len(cc5) == 1
        missing_text = " ".join(cc5[0].missing)
        assert "srcChainId" in missing_text
        assert "srcAddress" not in missing_text

    def test_no_flag_both_validated_in_require(self):
        findings = analyze_source(SAFE_BOTH_VALIDATED, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert cc5 == []

    def test_no_flag_trusted_remote_mapping(self):
        findings = analyze_source(SAFE_TRUSTED_REMOTE_MAPPING, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert cc5 == []

    def test_no_flag_non_handler_function(self):
        findings = analyze_source(SAFE_NOT_A_HANDLER, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert cc5 == []

    def test_no_flag_sg_receive_with_mapping_guard(self):
        findings = analyze_source(SAFE_SG_RECEIVE_MAPPING, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert cc5 == []

    def test_flags_receive_message_with_sender(self):
        findings = analyze_source(VULN_RECEIVE_MESSAGE_SENDER, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert len(cc5) == 1

    def test_finding_has_correct_key_var(self):
        findings = analyze_source(VULN_CELER_EXECUTE_MESSAGE, "test.sol")
        cc5 = [f for f in findings if f.rule == "CC-5"]
        assert "srcChainId" in cc5[0].key_var or "srcAddress" in cc5[0].key_var

    def test_cc5_independent_from_cc1(self):
        """CC-5 fires on message handler functions; CC-1 targets fulfillment idempotency keys."""
        findings = analyze_source(VULN_LZ_RECEIVE, "test.sol")
        rules = {f.rule for f in findings}
        assert "CC-5" in rules
        assert "CC-1" not in rules
