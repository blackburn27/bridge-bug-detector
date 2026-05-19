"""
Tests for CC-4 detector: ecrecover return value not checked against address(0).
"""

from bridge_detector.detector import analyze_source


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Vulnerable: ecrecover result stored in var, compared to trustedSigner, no null check
VULN_VAR_NO_NULL_CHECK = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;

    function mint(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));
        address signer = ecrecover(hash, v, r, s);
        require(signer == trustedSigner, "bad sig");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Vulnerable: inline ecrecover in require, no null check
VULN_INLINE_NO_NULL_CHECK = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;

    function withdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        require(ecrecover(hash, v, r, s) == trustedSigner, "invalid signature");
        payable(to).transfer(amount);
    }
}
"""

# Vulnerable: classic tutorial pattern — midas/CharonSoulBrige style
# (prefixed hash, ecrecover in function body, compared to from address)
VULN_PREFIXED_PATTERN = """
pragma solidity ^0.8.0;

contract Bridge {
    mapping(address => mapping(uint256 => bool)) public processedNonces;

    function mintBridge(address from, address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 message = prefixed(keccak256(abi.encodePacked(from, to, amount, nonce)));
        address recovered = ecrecover(message, v, r, s);
        require(recovered == from, "wrong signature");
        processedNonces[from][nonce] = true;
        _mint(to, amount);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", hash));
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: explicit != address(0) check before comparison
SAFE_EXPLICIT_NULL_CHECK = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;

    function mint(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "invalid signature");
        require(signer == trustedSigner, "wrong signer");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: inverse form — if (signer == address(0)) revert
SAFE_INVERSE_NULL_CHECK = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;

    function withdraw(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        require(signer == trustedSigner, "wrong signer");
        payable(to).transfer(amount);
    }

    error InvalidSignature();
}
"""

# Safe: uses OZ ECDSA.recover (reverts on address(0) internally)
SAFE_OZ_ECDSA = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Bridge {
    using ECDSA for bytes32;
    address public trustedSigner;

    function mint(address to, uint256 amount, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount, address(this)));
        address signer = hash.recover(sig);
        require(signer == trustedSigner, "bad sig");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: not a bridge function name — should not be flagged
SAFE_NON_BRIDGE_FUNCTION = """
pragma solidity ^0.8.0;

contract Governance {
    address public admin;

    function castVote(uint256 proposalId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(proposalId, msg.sender));
        address voter = ecrecover(hash, v, r, s);
        require(voter == admin, "not admin");
    }
}
"""

# Safe: ZERO_ADDRESS named constant used as null check
SAFE_ZERO_ADDRESS_CONSTANT = """
pragma solidity ^0.8.0;

contract Bridge {
    address public constant ZERO_ADDRESS = address(0);
    address public trustedSigner;

    function mint(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        address signer = ecrecover(hash, v, r, s);
        require(signer != ZERO_ADDRESS, "zero signer");
        require(signer == trustedSigner, "wrong signer");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Verify CC-4 doesn't interfere with CC-3 on the same function
VULN_BOTH_CC3_AND_CC4 = """
pragma solidity ^0.8.0;

contract Bridge {
    address public trustedSigner;

    function mint(address to, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, address(this)));
        address signer = ecrecover(hash, v, r, s);
        require(signer == trustedSigner, "bad sig");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCC4Detection:

    def test_flags_var_ecrecover_no_null_check(self):
        findings = analyze_source(VULN_VAR_NO_NULL_CHECK, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert len(cc4) == 1
        assert cc4[0].severity == "MEDIUM"
        assert cc4[0].function_name == "mint"

    def test_flags_inline_ecrecover_no_null_check(self):
        findings = analyze_source(VULN_INLINE_NO_NULL_CHECK, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert len(cc4) == 1
        assert cc4[0].function_name == "withdraw"

    def test_flags_prefixed_pattern(self):
        findings = analyze_source(VULN_PREFIXED_PATTERN, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert len(cc4) == 1
        assert cc4[0].function_name == "mintBridge"

    def test_no_flag_explicit_null_check(self):
        findings = analyze_source(SAFE_EXPLICIT_NULL_CHECK, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4 == []

    def test_no_flag_inverse_null_check(self):
        findings = analyze_source(SAFE_INVERSE_NULL_CHECK, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4 == []

    def test_no_flag_oz_ecdsa_recover(self):
        findings = analyze_source(SAFE_OZ_ECDSA, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4 == []

    def test_no_flag_non_bridge_function(self):
        findings = analyze_source(SAFE_NON_BRIDGE_FUNCTION, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4 == []

    def test_no_flag_zero_address_constant(self):
        findings = analyze_source(SAFE_ZERO_ADDRESS_CONSTANT, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4 == []

    def test_extracts_var_name(self):
        findings = analyze_source(VULN_VAR_NO_NULL_CHECK, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4[0].key_var == "signer"

    def test_extracts_var_name_recovered(self):
        findings = analyze_source(VULN_PREFIXED_PATTERN, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert cc4[0].key_var == "recovered"

    def test_missing_field_describes_fix(self):
        findings = analyze_source(VULN_VAR_NO_NULL_CHECK, "test.sol")
        cc4 = [f for f in findings if f.rule == "CC-4"]
        assert "address(0)" in cc4[0].missing[0]

    def test_cc3_and_cc4_both_fire_on_same_function(self):
        """A function can have both CC-3 (no chainId) and CC-4 (no null check)."""
        findings = analyze_source(VULN_BOTH_CC3_AND_CC4, "test.sol")
        rules = {f.rule for f in findings}
        assert "CC-3" in rules
        assert "CC-4" in rules

    def test_cc4_fires_independently_from_cc1_cc2(self):
        findings = analyze_source(VULN_VAR_NO_NULL_CHECK, "test.sol")
        rules = {f.rule for f in findings}
        assert "CC-4" in rules
        assert "CC-1" not in rules
        assert "CC-2" not in rules
