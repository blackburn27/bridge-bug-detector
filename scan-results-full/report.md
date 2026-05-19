# Bridge Bug Detector — Mass Scan Report

## Summary

| Metric | Value |
|--------|-------|
| Protocols scanned | 37 |
| Solidity files scanned | 4433 |
| Total findings | 2 |
| Protocols with findings | 2 |
| Scan time | 6.5s |

## Findings by Protocol

### Stargate Finance

Repo: https://github.com/stargate-protocol/stargate

#### `lzReceive()` — OmnichainFungibleToken.sol

- **Severity**: INFORMATIONAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/stargate-protocol__stargate/contracts/OmnichainFungibleToken.sol`
- **Line**: 89
- **Guard**: `(delegated to caller)[_nonce]`
- **Key args**: `uint64 _nonce`
- **Missing**: `contract-level mapping for _nonce (currently relies on trusted caller for replay protection)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Celer cBridge

Repo: https://github.com/celer-network/sgn-v2-contracts

#### `mint()` — PeggedBrc20Bridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/celer-network__sgn-v2-contracts/contracts/pegged-bridge/PeggedBrc20Bridge.sol`
- **Line**: 68
- **Guard**: `records[mintId]`
- **Key args**: `_receiver, _token, _amount, _depositor, _refChainId, _refId, address(this)`
- **Missing**: `destChainId / block.chainid`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

## Clean Protocols

| Protocol | Files |
|----------|-------|
| Across Protocol | 199 |
| Hop Protocol | 82 |
| Stargate v2 | 113 |
| Connext | 151 |
| Synapse Protocol | 232 |
| deBridge | 43 |
| Socket / Bungee | 60 |
| Axelar Gateway | 43 |
| Hyperlane | 234 |
| Wormhole | 60 |
| Wormhole NTT | 36 |
| LayerZero v1 | 37 |
| LayerZero v2 | 206 |
| Chainlink CCIP | 1036 |
| dln.trade (DLN) | 26 |
| Router Protocol CrossTalk | 20 |
| Li.Fi Contracts | 138 |
| Biconomy Hyphen | 77 |
| Optimism Standard Bridge | 46 |
| Arbitrum Bridge | 141 |
| Polygon zkEVM Bridge | 135 |
| Scroll Bridge | 1 |
| zkSync Bridge | 236 |
| Multichain (Anyswap) | 99 |
| Symbiosis Finance | 92 |
| Rubic Exchange | 54 |
| Hashflow | 35 |
| Allbridge Core | 48 |
| Router Protocol V2 | 222 |
| Bungee Refuel | 87 |
| Orbiter Finance | 38 |
| MAP Protocol | 47 |
| Flare Network | 170 |
| Rarimo Bridge | 39 |
| Meson Protocol | 3 |