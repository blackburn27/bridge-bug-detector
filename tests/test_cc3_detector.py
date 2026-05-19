"""
Tests for CC-3 detector: Missing chain ID in off-chain signature digest.
"""

from bridge_detector.detector import analyze_source


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Vulnerable: hand-rolled encodePacked hash, no chainId, ecrecover
VULN_ECRECOVER = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;
    mapping(bytes32 => bool) public used;

    function mint(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));
        require(ecrecover(hash, v, r, s) == trustedSigner, "bad sig");
        require(!used[hash]);
        used[hash] = true;
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Vulnerable: ECDSA.recover, no chainId in packed hash
VULN_ECDSA = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Bridge {
    using ECDSA for bytes32;
    address public trustedSigner;

    function fulfillBridge(address receiver, uint256 amount, bytes32 nonce, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(receiver, amount, nonce, address(this)));
        require(hash.recover(sig) == trustedSigner, "invalid sig");
        _mint(receiver, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: chainId included in encodePacked
SAFE_CHAIN_ID = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;

    function mint(address to, uint256 amount, uint256 nonce, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(block.chainid, to, amount, nonce, address(this)));
        require(ecrecover(hash, 27, bytes32(0), bytes32(0)) == trustedSigner);
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: uses EIP-712 domain separator
SAFE_EIP712_DOMAIN = """
pragma solidity ^0.8.0;

contract Bridge {
    bytes32 public DOMAIN_SEPARATOR;
    address public trustedSigner;

    function mint(address to, uint256 amount, bytes calldata sig) external {
        bytes32 structHash = keccak256(abi.encodePacked(to, amount));
        bytes32 hash = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, structHash));
        require(ecrecover(hash, 27, bytes32(0), bytes32(0)) == trustedSigner);
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: inherits OZ EIP712
SAFE_EIP712_INHERIT = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Bridge is EIP712 {
    using ECDSA for bytes32;

    constructor() EIP712("Bridge", "1") {}

    function mint(address to, uint256 amount, bytes calldata sig) external {
        bytes32 structHash = keccak256(abi.encodePacked(to, amount));
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(sig);
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: not a bridge/mint function
SAFE_NON_BRIDGE = """
pragma solidity ^0.8.0;

contract Governance {
    function vote(uint256 proposalId, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(proposalId, msg.sender));
        require(ecrecover(hash, 27, bytes32(0), bytes32(0)) != address(0));
    }
}
"""

# Safe: no signature verification at all
SAFE_NO_SIG = """
pragma solidity ^0.8.0;

contract Bridge {
    mapping(bytes32 => bool) public records;

    function mint(address to, uint256 amount, bytes32 txId) external {
        bytes32 key = keccak256(abi.encodePacked(to, amount, txId, address(this)));
        require(!records[key]);
        records[key] = true;
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCC3Detection:

    def test_flags_ecrecover_no_chainid(self):
        findings = analyze_source(VULN_ECRECOVER, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert len(cc3) == 1
        assert cc3[0].severity == "HIGH"
        assert cc3[0].function_name == "mint"

    def test_flags_ecdsa_recover_no_chainid(self):
        findings = analyze_source(VULN_ECDSA, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert len(cc3) == 1
        assert cc3[0].function_name == "fulfillBridge"

    def test_no_flag_when_chainid_present(self):
        findings = analyze_source(SAFE_CHAIN_ID, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert cc3 == []

    def test_no_flag_when_domain_separator_used(self):
        findings = analyze_source(SAFE_EIP712_DOMAIN, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert cc3 == []

    def test_no_flag_when_eip712_inherited(self):
        findings = analyze_source(SAFE_EIP712_INHERIT, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert cc3 == []

    def test_no_flag_non_bridge_function(self):
        findings = analyze_source(SAFE_NON_BRIDGE, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert cc3 == []

    def test_no_flag_no_signature_verification(self):
        findings = analyze_source(SAFE_NO_SIG, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert cc3 == []

    def test_finding_has_correct_rule(self):
        findings = analyze_source(VULN_ECRECOVER, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        assert cc3[0].rule == "CC-3"
        assert "block.chainid" in cc3[0].missing[0]

    def test_finding_extracts_present_args(self):
        findings = analyze_source(VULN_ECRECOVER, "test.sol")
        cc3 = [f for f in findings if f.rule == "CC-3"]
        args = cc3[0].present_args
        assert any("to" in a for a in args)
        assert any("amount" in a for a in args)

    def test_cc3_fires_independently(self):
        """CC-3 fires on its own; other rules may also fire if their patterns match."""
        findings = analyze_source(VULN_ECRECOVER, "test.sol")
        rules = {f.rule for f in findings}
        assert "CC-3" in rules
        # CC-2 should not fire (no unguarded txid param)
        assert "CC-2" not in rules
