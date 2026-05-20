"""Tests for CC-10: Single-key mint with no threshold signature verification."""
from bridge_detector.detector import analyze_source

VULN_RONIN_PATTERN = """
pragma solidity ^0.8.0;
contract RoninBridge {
    address public relayer;
    modifier onlyRelayer() {
        require(msg.sender == relayer);
        _;
    }

    function fulfillMint(address recipient, uint256 amount) external onlyRelayer {
        IToken(token).mint(recipient, amount);
    }

    address public token;
}
interface IToken { function mint(address, uint256) external; }
"""

VULN_OWNER_MINT = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";

contract Bridge is Ownable {
    function executeMint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
    function _mint(address, uint256) internal {}
}
"""

SAFE_THRESHOLD_SIGNATURES = """
pragma solidity ^0.8.0;
contract Bridge {
    uint256 public threshold;
    modifier onlyRelayer() { _; }

    function fulfillMint(
        address recipient,
        uint256 amount,
        bytes[] calldata signatures
    ) external onlyRelayer {
        require(signatures.length >= threshold, "insufficient signatures");
        bytes32 hash = keccak256(abi.encodePacked(recipient, amount));
        _verifySignatures(hash, signatures);
        _mint(recipient, amount);
    }
    function _verifySignatures(bytes32, bytes[] calldata) internal {}
    function _mint(address, uint256) internal {}
}
"""

SAFE_THRESHOLD_BODY_CHECK = """
pragma solidity ^0.8.0;
contract Bridge {
    modifier onlyValidator() { _; }

    function relayMint(address to, uint256 amount, bytes[] memory sigs) external onlyValidator {
        require(sigs.length >= quorum, "below quorum");
        _checkThreshold(keccak256(abi.encodePacked(to, amount)), sigs);
        _mint(to, amount);
    }
    uint256 public quorum;
    function _checkThreshold(bytes32, bytes[] memory) internal {}
    function _mint(address, uint256) internal {}
}
"""

SAFE_NO_SINGLE_ROLE = """
pragma solidity ^0.8.0;
contract Bridge {
    function completeMint(address to, uint256 amount, bytes[] calldata sigs) external {
        _verifySignatures(keccak256(abi.encodePacked(to, amount)), sigs);
        _mint(to, amount);
    }
    function _verifySignatures(bytes32, bytes[] calldata) internal {}
    function _mint(address, uint256) internal {}
}
"""

SAFE_NO_MINT_CALL = """
pragma solidity ^0.8.0;
contract Bridge {
    modifier onlyRelayer() { _; }

    function fulfillBridge(address to, uint256 amount) external onlyRelayer {
        IERC20(token).transfer(to, amount);
    }
    address public token;
}
interface IERC20 { function transfer(address, uint256) external returns (bool); }
"""


class TestCC10Detection:

    def test_flags_ronin_pattern(self):
        findings = analyze_source(VULN_RONIN_PATTERN, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert len(cc10) == 1
        assert cc10[0].severity == "HIGH"
        assert cc10[0].function_name == "fulfillMint"

    def test_flags_owner_mint(self):
        findings = analyze_source(VULN_OWNER_MINT, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert len(cc10) == 1
        assert cc10[0].function_name == "executeMint"

    def test_no_flag_threshold_signatures(self):
        findings = analyze_source(SAFE_THRESHOLD_SIGNATURES, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert cc10 == []

    def test_no_flag_threshold_body_check(self):
        findings = analyze_source(SAFE_THRESHOLD_BODY_CHECK, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert cc10 == []

    def test_no_flag_no_single_role(self):
        findings = analyze_source(SAFE_NO_SINGLE_ROLE, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert cc10 == []

    def test_no_flag_no_mint_call(self):
        findings = analyze_source(SAFE_NO_MINT_CALL, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert cc10 == []

    def test_missing_field_mentions_exploit(self):
        findings = analyze_source(VULN_RONIN_PATTERN, "test.sol")
        cc10 = [f for f in findings if f.rule == "CC-10"]
        assert "Ronin" in cc10[0].missing[0]
