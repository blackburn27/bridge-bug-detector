"""
Tests for the Bridge Bug Detector.

Golden case: the real Ripio BridgeDeposit.sol CC-1 bug.
"""

import pytest
from pathlib import Path

from bridge_detector.detector import analyze_source, Finding
from bridge_detector.parser import extract_functions, extract_replay_guard_mappings

RIPIO_CONTRACT = Path("/home/kali/web3/BugBounty/Ripio/latam-stables/src/BridgeDeposit.sol")


# ---------------------------------------------------------------------------
# Minimal inline fixtures
# ---------------------------------------------------------------------------

VULNERABLE_SNIPPET = """
pragma solidity ^0.8.0;

contract Bridge {
    mapping(bytes32 => bool) public bridgeFulfilled;

    function fulfillBridgeMint(
        address token,
        address to,
        uint256 amount,
        uint256 sourceChainId,
        bytes32 sourceTxHash,
        uint256 sourceDepositId
    ) external {
        bytes32 fulfillmentKey = keccak256(
            abi.encodePacked(sourceChainId, sourceTxHash, sourceDepositId)
        );
        if (bridgeFulfilled[fulfillmentKey]) revert();
        bridgeFulfilled[fulfillmentKey] = true;
    }
}
"""

SAFE_SNIPPET = """
pragma solidity ^0.8.0;

contract BridgeSafe {
    mapping(bytes32 => bool) public bridgeFulfilled;

    function fulfillBridgeMint(
        uint256 sourceChainId,
        bytes32 sourceTxHash,
        uint256 sourceDepositId
    ) external {
        bytes32 fulfillmentKey = keccak256(
            abi.encodePacked(sourceChainId, sourceTxHash, sourceDepositId, block.chainid)
        );
        if (bridgeFulfilled[fulfillmentKey]) revert();
        bridgeFulfilled[fulfillmentKey] = true;
    }
}
"""

SAFE_DEST_PARAM_SNIPPET = """
pragma solidity ^0.8.0;

contract BridgeSafe2 {
    mapping(bytes32 => bool) public bridgeFulfilled;

    function fulfillBridgeMint(
        uint256 sourceChainId,
        bytes32 sourceTxHash,
        uint256 sourceDepositId,
        uint256 destChainId
    ) external {
        bytes32 fulfillmentKey = keccak256(
            abi.encodePacked(sourceChainId, sourceTxHash, sourceDepositId, destChainId)
        );
        if (bridgeFulfilled[fulfillmentKey]) revert();
        bridgeFulfilled[fulfillmentKey] = true;
    }
}
"""

NO_GUARD_SNIPPET = """
pragma solidity ^0.8.0;

contract NotABridge {
    function computeHash(uint256 a, bytes32 b) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}
"""

# Inline form: mapping[keccak256(abi.encodePacked(...))] without a temp variable
INLINE_VULNERABLE_SNIPPET = """
pragma solidity ^0.8.0;

contract BridgeInline {
    mapping(bytes32 => bool) public processed;

    function fulfillRelay(
        uint256 sourceChainId,
        bytes32 sourceTxHash,
        uint256 nonce
    ) external {
        require(!processed[keccak256(abi.encodePacked(sourceChainId, sourceTxHash, nonce))], "done");
        processed[keccak256(abi.encodePacked(sourceChainId, sourceTxHash, nonce))] = true;
    }
}
"""

INLINE_SAFE_SNIPPET = """
pragma solidity ^0.8.0;

contract BridgeInlineSafe {
    mapping(bytes32 => bool) public processed;

    function fulfillRelay(
        uint256 sourceChainId,
        bytes32 sourceTxHash,
        uint256 nonce
    ) external {
        require(
            !processed[keccak256(abi.encodePacked(sourceChainId, sourceTxHash, nonce, block.chainid))],
            "done"
        );
        processed[keccak256(abi.encodePacked(sourceChainId, sourceTxHash, nonce, block.chainid))] = true;
    }
}
"""


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParser:
    def test_extracts_replay_guard_mappings(self):
        mappings = extract_replay_guard_mappings(VULNERABLE_SNIPPET)
        assert "bridgeFulfilled" in mappings

    def test_extracts_function(self):
        funcs = extract_functions(VULNERABLE_SNIPPET)
        names = [f.name for f in funcs]
        assert "fulfillBridgeMint" in names

    def test_extracts_key_args(self):
        funcs = extract_functions(VULNERABLE_SNIPPET)
        fulfill = next(f for f in funcs if f.name == "fulfillBridgeMint")
        assert fulfill.encoded_keys, "Should find encoded key"
        ek = fulfill.encoded_keys[0]
        assert ek.var_name == "fulfillmentKey"
        assert any("sourceChainId" in a for a in ek.args)
        assert any("sourceTxHash" in a for a in ek.args)
        assert any("sourceDepositId" in a for a in ek.args)

    def test_extracts_replay_guard_usage(self):
        funcs = extract_functions(VULNERABLE_SNIPPET)
        fulfill = next(f for f in funcs if f.name == "fulfillBridgeMint")
        assert fulfill.replay_guards, "Should detect guard usage"
        assert fulfill.replay_guards[0].mapping_name == "bridgeFulfilled"
        assert fulfill.replay_guards[0].key_var == "fulfillmentKey"


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------

class TestDetector:
    def test_flags_vulnerable_snippet(self):
        findings = analyze_source(VULNERABLE_SNIPPET, "test.sol")
        assert len(findings) == 1
        f = findings[0]
        assert f.function_name == "fulfillBridgeMint"
        assert "destChainId / block.chainid" in f.missing[0]
        assert f.severity == "HIGH"

    def test_no_findings_when_block_chainid_present(self):
        findings = analyze_source(SAFE_SNIPPET, "test.sol")
        assert findings == []

    def test_no_findings_when_dest_chain_param_present(self):
        findings = analyze_source(SAFE_DEST_PARAM_SNIPPET, "test.sol")
        assert findings == []

    def test_no_findings_without_replay_guard(self):
        findings = analyze_source(NO_GUARD_SNIPPET, "test.sol")
        assert findings == []

    def test_finding_has_correct_guard_name(self):
        findings = analyze_source(VULNERABLE_SNIPPET, "test.sol")
        assert findings[0].guard_mapping == "bridgeFulfilled"

    def test_finding_has_present_args(self):
        findings = analyze_source(VULNERABLE_SNIPPET, "test.sol")
        args = findings[0].present_args
        assert any("sourceChainId" in a for a in args)

    def test_flags_inline_vulnerable(self):
        findings = analyze_source(INLINE_VULNERABLE_SNIPPET, "test.sol")
        assert len(findings) >= 1
        assert findings[0].function_name == "fulfillRelay"
        assert "destChainId / block.chainid" in findings[0].missing[0]

    def test_no_findings_inline_safe(self):
        findings = analyze_source(INLINE_SAFE_SNIPPET, "test.sol")
        assert findings == []


# ---------------------------------------------------------------------------
# Integration: real Ripio contract
# ---------------------------------------------------------------------------

class TestRipioContract:
    @pytest.mark.skipif(
        not RIPIO_CONTRACT.exists(),
        reason="Ripio contract not present on this machine",
    )
    def test_detects_cc1_in_ripio(self):
        source = RIPIO_CONTRACT.read_text()
        findings = analyze_source(source, str(RIPIO_CONTRACT))
        assert findings, "Should detect CC-1 in BridgeDeposit.sol"
        funcs = [f.function_name for f in findings]
        assert "fulfillBridgeMint" in funcs

    @pytest.mark.skipif(
        not RIPIO_CONTRACT.exists(),
        reason="Ripio contract not present on this machine",
    )
    def test_ripio_finding_line_approximate(self):
        source = RIPIO_CONTRACT.read_text()
        findings = analyze_source(source, str(RIPIO_CONTRACT))
        cc1 = next(f for f in findings if f.function_name == "fulfillBridgeMint")
        # Key is at line ~397; allow ±20 lines for body-offset arithmetic
        assert 370 <= cc1.line <= 420, f"Expected line ~397, got {cc1.line}"
