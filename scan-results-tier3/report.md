# Bridge Bug Detector — Mass Scan Report

## Summary

| Metric | Value |
|--------|-------|
| Protocols scanned | 20 |
| Solidity files scanned | 1153 |
| Total findings | 40 |
| Protocols with findings | 10 |
| Scan time | 2.1s |

## Findings by Protocol

### Gnosis Omnibridge

Repo: https://github.com/omni/omnibridge

#### `executeMessageCall()` — AMBMock.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/omni__omnibridge/contracts/mocks/AMBMock.sol`
- **Line**: 21
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_contract, _sender, _data, _messageId, _gas`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Gnosis AMB Bridge

Repo: https://github.com/omni/tokenbridge-contracts

#### `safeTransferFrom()` — SafeERC20.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/omni__tokenbridge-contracts/contracts/libraries/SafeERC20.sol`
- **Line**: 38
- **Guard**: `(none — zero address unchecked)[_token]`
- **Key args**: `_token`
- **Missing**: `require(_token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_executeMessage()` — BasicForeignAMB.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/omni__tokenbridge-contracts/contracts/upgradeable_contracts/arbitrary_message/BasicForeignAMB.sol`
- **Line**: 98
- **Guard**: `(none — source not bound)[sender]`
- **Key args**: `sender`
- **Missing**: `source address `sender` never validated`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `processMessage()` — MessageProcessor.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/omni__tokenbridge-contracts/contracts/upgradeable_contracts/arbitrary_message/MessageProcessor.sol`
- **Line**: 182
- **Guard**: `(none — source not bound)[_sourceChainId, _sender]`
- **Key args**: `_sourceChainId, _sender`
- **Missing**: `source chain `_sourceChainId` never validated, source address `_sender` never validated`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Linea Bridge

Repo: https://github.com/Consensys/linea-contracts

#### `bridgeToken()` — TokenBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Consensys__linea-contracts/contracts/tokenBridge/TokenBridge.sol`
- **Line**: 151
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `bridgeToken()` — TokenBridge.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Consensys__linea-contracts/contracts/tokenBridge/TokenBridge.sol`
- **Line**: 151
- **Guard**: `(none — zero address unchecked)[_token]`
- **Key args**: `_token`
- **Missing**: `require(_token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `bridgeTokenWithPermit()` — TokenBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Consensys__linea-contracts/contracts/tokenBridge/TokenBridge.sol`
- **Line**: 212
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mint()` — BridgedToken.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Consensys__linea-contracts/contracts/tokenBridge/BridgedToken.sol`
- **Line**: 48
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendMessage()` — MockMessageService.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Consensys__linea-contracts/contracts/tokenBridge/mocks/MockMessageService.sol`
- **Line**: 10
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_to, _fee, _calldata`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Blast Bridge

Repo: https://github.com/blast-io/blast

#### `mint()` — MintManager.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/governance/MintManager.sol`
- **Line**: 42
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mint()` — GovernanceToken.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/governance/GovernanceToken.sol`
- **Line**: 22
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mint()` — OptimismMintableERC20.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/universal/OptimismMintableERC20.sol`
- **Line**: 64
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `finalizeBridgeETH()` — L1BlastBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/mainnet-bridge/L1BlastBridge.sol`
- **Line**: 151
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `finalizeBridgeETH()` — L1StandardBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/L1/L1StandardBridge.sol`
- **Line**: 168
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositTransaction()` — OptimismPortal.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/L1/OptimismPortal.sol`
- **Line**: 411
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `finalizeDeposit()` — L2StandardBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/blast-io__blast/blast-optimism/packages/contracts-bedrock/src/L2/L2StandardBridge.sol`
- **Line**: 143
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### zkLink Nova

Repo: https://github.com/zkLinkProtocol/zklink-contracts

#### `deposit()` — ZkLink.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/zkLinkProtocol__zklink-contracts/contracts/ZkLink.sol`
- **Line**: 644
- **Guard**: `(none — zero address unchecked)[_tokenAddress]`
- **Key args**: `_tokenAddress`
- **Missing**: `require(_tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mintTo()` — FaucetToken.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/zkLinkProtocol__zklink-contracts/contracts/dev-contracts/FaucetToken.sol`
- **Line**: 20
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — LineaL1Gateway.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/zkLinkProtocol__zklink-contracts/contracts/gateway/linea/LineaL1Gateway.sol`
- **Line**: 48
- **Guard**: `(none — zero address unchecked)[_token]`
- **Key args**: `_token`
- **Missing**: `require(_token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — ZkSyncL1Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/zkLinkProtocol__zklink-contracts/contracts/gateway/zksync/ZkSyncL1Gateway.sol`
- **Line**: 97
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — ZkSyncL1Gateway.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/zkLinkProtocol__zklink-contracts/contracts/gateway/zksync/ZkSyncL1Gateway.sol`
- **Line**: 97
- **Guard**: `(none — zero address unchecked)[_token]`
- **Key args**: `_token`
- **Missing**: `require(_token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Sygma Protocol

Repo: https://github.com/sygmaprotocol/sygma-solidity

#### `lockERC721()` — ERC721Safe.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/sygmaprotocol__sygma-solidity/contracts/ERC721Safe.sol`
- **Line**: 22
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `execute()` — TestContracts.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/sygmaprotocol__sygma-solidity/contracts/TestContracts.sol`
- **Line**: 83
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `data, to, sender`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `deposit()` — GmpTransferAdapter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/sygmaprotocol__sygma-solidity/contracts/adapters/GmpTransferAdapter.sol`
- **Line**: 61
- **Guard**: `(none — msg.value unchecked)[tokenAmount]`
- **Key args**: `tokenAmount`
- **Missing**: `require(msg.value == tokenAmount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Rango Exchange

Repo: https://github.com/rango-exchange/rango-contracts-v2

#### `sendTokenWithMessageThroughRango()` — SampleDApp.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/utils/SampleDApp.sol`
- **Line**: 55
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `rangoContractToCall, token, amount, rangoCallData`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `fetchTokenFromRouterAndRefund()` — RangoSymbiosisMiddleware.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/facets/bridges/RangoSymbiosisMiddleware.sol`
- **Line**: 67
- **Guard**: `(none — zero address unchecked)[_tokenAddress]`
- **Key args**: `_tokenAddress`
- **Missing**: `require(_tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `executeMessageWithTransferRefund()` — RangoCBridgeMiddleware.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/facets/bridges/cbridge/RangoCBridgeMiddleware.sol`
- **Line**: 76
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `executeMessageWithTransfer()` — RangoCBridgeMiddleware.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/facets/bridges/cbridge/RangoCBridgeMiddleware.sol`
- **Line**: 123
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `executeMessageWithTransferFallback()` — RangoCBridgeMiddleware.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/facets/bridges/cbridge/RangoCBridgeMiddleware.sol`
- **Line**: 149
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `doSend()` — RangoCBridgeMiddleware.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/facets/bridges/cbridge/RangoCBridgeMiddleware.sol`
- **Line**: 196
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `executeMessage()` — MessageReceiverApp.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/rango-exchange__rango-contracts-v2/contracts/facets/bridges/cbridge/im/message/framework/MessageReceiverApp.sol`
- **Line**: 78
- **Guard**: `(none — source not bound)[_srcChainId, _sender]`
- **Key args**: `_srcChainId, _sender`
- **Missing**: `source chain `_srcChainId` never validated, source address `_sender` never validated`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Gravity Bridge

Repo: https://github.com/Gravity-Bridge/Gravity-Bridge

#### `verifySig()` — Gravity.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Gravity-Bridge__Gravity-Bridge/solidity/contracts/Gravity.sol`
- **Line**: 153
- **Guard**: `ECDSA.recover / ecrecover[hash]`
- **Key args**: `"\x19Ethereum Signed Message:\n32", _theHash`
- **Missing**: `block.chainid in signed message digest`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Mantle Bridge

Repo: https://github.com/mantlenetworkio/mantle

#### `relayMessage()` — L2CrossDomainMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/mantlenetworkio__mantle/packages/contracts/contracts/L2/messaging/L2CrossDomainMessenger.sol`
- **Line**: 144
- **Guard**: `relayedMessages[relayId]`
- **Key args**: `xDomainCalldata, msg.sender, block.number`
- **Missing**: `destChainId / block.chainid`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessage()` — L2CrossDomainMessenger.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/mantlenetworkio__mantle/packages/contracts/contracts/L2/messaging/L2CrossDomainMessenger.sol`
- **Line**: 92
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_target, _sender, _message, _messageNonce`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mint()` — TestMantleToken.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/mantlenetworkio__mantle/packages/contracts/contracts/L1/local/TestMantleToken.sol`
- **Line**: 103
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_depositInto()` — DelegationManager.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/mantlenetworkio__mantle/packages/contracts/contracts/L1/delegation/DelegationManager.sol`
- **Line**: 436
- **Guard**: `(none — zero address unchecked)[token]`
- **Key args**: `token`
- **Missing**: `require(token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessage()` — L1CrossDomainMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/mantlenetworkio__mantle/packages/contracts/contracts/L1/messaging/L1CrossDomainMessenger.sol`
- **Line**: 239
- **Guard**: `relayedMessages[relayId]`
- **Key args**: `xDomainCalldata, msg.sender, block.number`
- **Missing**: `destChainId / block.chainid`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessage()` — L1CrossDomainMessenger.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/mantlenetworkio__mantle/packages/contracts/contracts/L1/messaging/L1CrossDomainMessenger.sol`
- **Line**: 189
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_target, _sender, _message, _messageNonce, _proof`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### dForce xDODO Bridge

Repo: https://github.com/dforce-network/LendingContractsV2

#### `transferEthOut()` — Token.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/dforce-network__LendingContractsV2/contracts/mock/Token.sol`
- **Line**: 34
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mint()` — MSD.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/dforce-network__LendingContractsV2/contracts/msd/MSD.sol`
- **Line**: 108
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

## Clean Protocols

| Protocol | Files |
|----------|-------|
| pNetwork v3 | 39 |
| Taiko Bridge | 144 |
| Teleport MakerDAO | 0 |
| Nomad Bridge | 43 |

## Failed Clones

- XY Finance (https://github.com/XY-Finance/xy-finance-contracts)
- Kroma Bridge (https://github.com/wemade-kroma/kroma)
- Owlto Finance (https://github.com/owlto-finance/owlto-contract)
- Polymer Protocol (https://github.com/polymerdao/polymer-contracts)
- Everclear (Connext v2) (https://github.com/connext/everclear)
- Interport Finance (https://github.com/interport-finance/interport-finance-contracts)