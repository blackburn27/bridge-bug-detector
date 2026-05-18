"""
Tests for the CC-2 detector: Missing source-tx idempotency guard.

Golden case: the real Adshares WrappedADS contract.
"""

import pytest
from bridge_detector.detector import analyze_source
from bridge_detector.cc2_detector import (
    _find_tx_identifier_params,
    _param_has_replay_guard,
    _has_mint_op,
)
from bridge_detector.parser import extract_functions


# ---------------------------------------------------------------------------
# Inline fixtures
# ---------------------------------------------------------------------------

# Exact Adshares pattern — txid logged but never stored
ADSHARES_SNIPPET = """
pragma solidity ^0.5.17;

contract WrappedADS {
    mapping (address => uint256) private _minterAllowances;

    function wrapTo(address account, uint256 amount, uint64 from, uint64 txid)
        public returns (bool) {
        emit Wrap(account, from, txid, amount);
        _mint(account, amount);
        return true;
    }
}
"""

# Safe: txid checked and stored directly
SAFE_DIRECT_GUARD = """
pragma solidity ^0.8.0;

contract SafeBridge {
    mapping(uint64 => bool) public usedTxids;

    function wrapTo(address account, uint256 amount, uint64 from, uint64 txid)
        external {
        require(!usedTxids[txid], "already used");
        usedTxids[txid] = true;
        _mint(account, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: txid packed into keccak256, result stored
SAFE_KECCAK_GUARD = """
pragma solidity ^0.8.0;

contract SafeBridge2 {
    mapping(bytes32 => bool) public processed;

    function wrapTo(address account, uint256 amount, uint64 from, uint64 txid)
        external {
        bytes32 key = keccak256(abi.encodePacked(from, txid));
        require(!processed[key], "already processed");
        processed[key] = true;
        _mint(account, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Safe: txid in keccak inline inside mapping index
SAFE_INLINE_KECCAK = """
pragma solidity ^0.8.0;

contract SafeBridge3 {
    mapping(bytes32 => bool) public processed;

    function fulfillRelay(address to, uint256 amount, bytes32 txid) external {
        require(!processed[keccak256(abi.encodePacked(txid))], "done");
        processed[keccak256(abi.encodePacked(txid))] = true;
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Not a bridge function — no bridge keyword in name
NOT_A_BRIDGE = """
pragma solidity ^0.8.0;

contract Token {
    function transfer(address to, uint256 amount, uint64 txid) external {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
}
"""

# Has txid param but no mint — should not flag
NO_MINT = """
pragma solidity ^0.8.0;

contract Bridge {
    function wrapTo(address account, uint256 amount, uint64 txid) external view returns (bytes32) {
        return keccak256(abi.encodePacked(txid));
    }
}
"""

# Multiple txid-like params — both unguarded → two findings
MULTI_UNGUARDED = """
pragma solidity ^0.8.0;

contract MultiParam {
    function fulfillBridge(
        address to,
        uint256 amount,
        bytes32 txid,
        uint256 nonce
    ) external {
        emit Processed(txid, nonce);
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {}
    event Processed(bytes32 txid, uint256 nonce);
}
"""


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestCC2Detection:

    def test_flags_adshares_pattern(self):
        findings = analyze_source(ADSHARES_SNIPPET, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert len(cc2) == 1
        assert cc2[0].function_name == "wrapTo"
        assert cc2[0].key_var == "txid"
        assert cc2[0].severity == "HIGH"

    def test_no_flag_direct_guard(self):
        findings = analyze_source(SAFE_DIRECT_GUARD, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert cc2 == []

    def test_no_flag_keccak_guard(self):
        findings = analyze_source(SAFE_KECCAK_GUARD, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert cc2 == []

    def test_no_flag_inline_keccak_guard(self):
        findings = analyze_source(SAFE_INLINE_KECCAK, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert cc2 == []

    def test_no_flag_non_bridge_function(self):
        findings = analyze_source(NOT_A_BRIDGE, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert cc2 == []

    def test_no_flag_when_no_mint(self):
        findings = analyze_source(NO_MINT, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert cc2 == []

    def test_finding_guard_mapping_label(self):
        findings = analyze_source(ADSHARES_SNIPPET, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        assert "(none" in cc2[0].guard_mapping

    def test_finding_to_dict_has_rule(self):
        findings = analyze_source(ADSHARES_SNIPPET, "test.sol")
        cc2 = [f for f in findings if f.rule == "CC-2"]
        d = cc2[0].to_dict()
        assert d["rule"] == "CC-2"
        assert d["missing_fields"]


class TestCC2Helpers:

    def test_find_tx_identifier_params(self):
        funcs = extract_functions(ADSHARES_SNIPPET)
        wrapTo = next(f for f in funcs if f.name == "wrapTo")
        tx_params = _find_tx_identifier_params(wrapTo)
        names = [n for _, n in tx_params]
        assert "txid" in names

    def test_param_not_guarded_in_adshares(self):
        funcs = extract_functions(ADSHARES_SNIPPET)
        wrapTo = next(f for f in funcs if f.name == "wrapTo")
        assert not _param_has_replay_guard(wrapTo.body, "txid")

    def test_param_guarded_direct(self):
        funcs = extract_functions(SAFE_DIRECT_GUARD)
        wrapTo = next(f for f in funcs if f.name == "wrapTo")
        assert _param_has_replay_guard(wrapTo.body, "txid")

    def test_param_guarded_via_keccak(self):
        funcs = extract_functions(SAFE_KECCAK_GUARD)
        wrapTo = next(f for f in funcs if f.name == "wrapTo")
        assert _param_has_replay_guard(wrapTo.body, "txid")

    def test_has_mint_op(self):
        assert _has_mint_op("_mint(account, amount);")
        assert _has_mint_op("token.mint(to, amount);")
        assert not _has_mint_op("emit Transfer(from, to, amount);")


class TestCC1StillWorks:
    """Regression: CC-1 rule must keep passing alongside CC-2."""

    def test_cc1_still_fires(self):
        CC1_SNIPPET = """
        pragma solidity ^0.8.0;
        contract Bridge {
            mapping(bytes32 => bool) public bridgeFulfilled;
            function fulfillBridgeMint(
                address to, uint256 amount,
                uint256 sourceChainId, bytes32 sourceTxHash, uint256 sourceDepositId
            ) external {
                bytes32 key = keccak256(abi.encodePacked(sourceChainId, sourceTxHash, sourceDepositId));
                if (bridgeFulfilled[key]) revert();
                bridgeFulfilled[key] = true;
                _mint(to, amount);
            }
            function _mint(address to, uint256 amount) internal {}
        }
        """
        findings = analyze_source(CC1_SNIPPET, "test.sol")
        cc1 = [f for f in findings if f.rule == "CC-1"]
        assert len(cc1) >= 1

    def test_both_rules_independent(self):
        """A contract can trigger both CC-1 and CC-2 at once."""
        BOTH = """
        pragma solidity ^0.8.0;
        contract DoubleBug {
            mapping(bytes32 => bool) public fulfilled;

            function fulfillBridge(
                address to, uint256 amount,
                uint256 sourceChainId, bytes32 sourceTxHash, uint64 txid
            ) external {
                bytes32 key = keccak256(abi.encodePacked(sourceChainId, sourceTxHash));
                if (fulfilled[key]) revert();
                fulfilled[key] = true;
                emit Processed(txid);
                _mint(to, amount);
            }
            function _mint(address to, uint256 amount) internal {}
            event Processed(uint64 txid);
        }
        """
        findings = analyze_source(BOTH, "test.sol")
        rules = {f.rule for f in findings}
        assert "CC-1" in rules
        assert "CC-2" in rules
