"""Tests for CC-8: Merkle proof not consumed after verification."""
from bridge_detector.detector import analyze_source

VULN_BNB_PATTERN = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Bridge {
    bytes32 public merkleRoot;
    mapping(address => uint256) public balances;

    function withdraw(bytes32[] calldata proof, bytes32 leaf, uint256 amount) external {
        require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid proof");
        balances[msg.sender] += amount;
    }
}
"""

VULN_CLAIM_PATTERN = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Airdrop {
    bytes32 public root;

    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(proof, root, leaf));
        _transfer(account, amount);
    }
    function _transfer(address, uint256) internal {}
}
"""

SAFE_PROOF_CONSUMED = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Bridge {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public usedProofs;

    function withdraw(bytes32[] calldata proof, bytes32 leaf, uint256 amount) external {
        bytes32 proofHash = keccak256(abi.encodePacked(proof, leaf));
        require(!usedProofs[proofHash], "proof already used");
        usedProofs[proofHash] = true;
        require(MerkleProof.verify(proof, merkleRoot, leaf), "invalid proof");
        payable(msg.sender).transfer(amount);
    }
}
"""

SAFE_LEAF_CONSUMED = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Bridge {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public claimedLeaves;

    function claim(bytes32[] calldata proof, bytes32 leaf) external {
        require(!claimedLeaves[leaf], "already claimed");
        require(MerkleProof.verify(proof, merkleRoot, leaf));
        claimedLeaves[leaf] = true;
        _release(msg.sender);
    }
    function _release(address) internal {}
}
"""

SAFE_NO_VALUE_RELEASE = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Verifier {
    bytes32 public root;

    function verify(bytes32[] calldata proof, bytes32 leaf) external view returns (bool) {
        return MerkleProof.verify(proof, root, leaf);
    }
}
"""

SAFE_NOT_CLAIM_FUNCTION = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract Bridge {
    bytes32 public root;

    function updateRoot(bytes32[] calldata proof, bytes32 leaf) external {
        require(MerkleProof.verify(proof, root, leaf));
        root = leaf;
    }
}
"""


class TestCC8Detection:

    def test_flags_bnb_pattern(self):
        findings = analyze_source(VULN_BNB_PATTERN, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert len(cc8) == 1
        assert cc8[0].severity == "CRITICAL"
        assert cc8[0].function_name == "withdraw"

    def test_flags_claim_pattern(self):
        findings = analyze_source(VULN_CLAIM_PATTERN, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert len(cc8) == 1
        assert cc8[0].function_name == "claim"

    def test_no_flag_proof_consumed(self):
        findings = analyze_source(SAFE_PROOF_CONSUMED, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert cc8 == []

    def test_no_flag_leaf_consumed(self):
        findings = analyze_source(SAFE_LEAF_CONSUMED, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert cc8 == []

    def test_no_flag_view_only_verify(self):
        findings = analyze_source(SAFE_NO_VALUE_RELEASE, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert cc8 == []

    def test_no_flag_non_claim_name(self):
        findings = analyze_source(SAFE_NOT_CLAIM_FUNCTION, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert cc8 == []

    def test_severity_critical(self):
        findings = analyze_source(VULN_BNB_PATTERN, "test.sol")
        cc8 = [f for f in findings if f.rule == "CC-8"]
        assert cc8[0].severity == "CRITICAL"
