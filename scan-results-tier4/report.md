# Bridge Bug Detector — Mass Scan Report

## Summary

| Metric | Value |
|--------|-------|
| Protocols scanned | 20 |
| Solidity files scanned | 742 |
| Total findings | 63 |
| Protocols with findings | 6 |
| Scan time | 1.7s |

## Findings by Protocol

### Scroll Bridge Contracts

Repo: https://github.com/scroll-tech/scroll-contracts

#### `finalizeDepositERC20()` — L2LidoGateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/lido/L2LidoGateway.sol`
- **Line**: 120
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_transferToken()` — L2BatchBridgeGateway.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/batch-bridge/L2BatchBridgeGateway.sol`
- **Line**: 229
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `token, receiver, amount`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_execute()` — ScrollOwner.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/misc/ScrollOwner.sol`
- **Line**: 133
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_target, _value, _data`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `execute()` — Fallback.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/misc/Fallback.sol`
- **Line**: 32
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_target, _data`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `deposit()` — L1WETHGatewayValidium.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/validium/L1WETHGatewayValidium.sol`
- **Line**: 53
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — L1ERC20GatewayValidium.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/validium/L1ERC20GatewayValidium.sol`
- **Line**: 117
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — L1ERC20GatewayValidium.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/validium/L1ERC20GatewayValidium.sol`
- **Line**: 128
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_transferERC20In()` — L1ERC20GatewayValidium.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/validium/L1ERC20GatewayValidium.sol`
- **Line**: 190
- **Guard**: `(none — zero address unchecked)[_token]`
- **Key args**: `_token`
- **Missing**: `require(_token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendMessage()` — L1ScrollMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/L1ScrollMessenger.sol`
- **Line**: 155
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendMessage()` — L1ScrollMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/L1ScrollMessenger.sol`
- **Line**: 165
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessageWithProof()` — L1ScrollMessenger.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/L1ScrollMessenger.sol`
- **Line**: 176
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_from, _to, _value, _nonce, _message, _proof`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendMessage()` — L2ScrollMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L2/L2ScrollMessenger.sol`
- **Line**: 70
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendMessage()` — L2ScrollMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L2/L2ScrollMessenger.sol`
- **Line**: 80
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_executeMessage()` — L2ScrollMessenger.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L2/L2ScrollMessenger.sol`
- **Line**: 143
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_from, _to, _value, _message, _xDomainCalldataHash`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `finalizeDepositERC20()` — L2ReverseCustomERC20Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L2/gateways/L2ReverseCustomERC20Gateway.sol`
- **Line**: 63
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositETH()` — L1ETHGateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ETHGateway.sol`
- **Line**: 58
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositETH()` — L1ETHGateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ETHGateway.sol`
- **Line**: 63
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositETHAndCall()` — L1ETHGateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ETHGateway.sol`
- **Line**: 72
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — L1GatewayRouter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1GatewayRouter.sol`
- **Line**: 129
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — L1GatewayRouter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1GatewayRouter.sol`
- **Line**: 138
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20AndCall()` — L1GatewayRouter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1GatewayRouter.sol`
- **Line**: 148
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositETH()` — L1GatewayRouter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1GatewayRouter.sol`
- **Line**: 189
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositETH()` — L1GatewayRouter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1GatewayRouter.sol`
- **Line**: 194
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositETHAndCall()` — L1GatewayRouter.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1GatewayRouter.sol`
- **Line**: 203
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — L1ERC20Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ERC20Gateway.sol`
- **Line**: 32
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20()` — L1ERC20Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ERC20Gateway.sol`
- **Line**: 41
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20AndCall()` — L1ERC20Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ERC20Gateway.sol`
- **Line**: 51
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_transferERC20In()` — L1ERC20Gateway.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ERC20Gateway.sol`
- **Line**: 115
- **Guard**: `(none — zero address unchecked)[_token]`
- **Key args**: `_token`
- **Missing**: `require(_token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendTransaction()` — EnforcedTxGateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/EnforcedTxGateway.sol`
- **Line**: 100
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendTransaction()` — EnforcedTxGateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/EnforcedTxGateway.sol`
- **Line**: 127
- **Guard**: `(none — msg.value unchecked)[_value]`
- **Key args**: `_value`
- **Missing**: `require(msg.value == _value) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC1155()` — L1ERC1155Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ERC1155Gateway.sol`
- **Line**: 66
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC1155()` — L1ERC1155Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/scroll-tech__scroll-contracts/src/L1/gateways/L1ERC1155Gateway.sol`
- **Line**: 76
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Synapse Messaging

Repo: https://github.com/synapsecns/sanguine

#### `deposit()` — SimpleVaultMock.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/synapsecns__sanguine/packages/contracts-rfq/test/mocks/SimpleVaultMock.sol`
- **Line**: 12
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_deposit()` — VaultMock.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/synapsecns__sanguine/packages/contracts-rfq/test/mocks/VaultMock.sol`
- **Line**: 20
- **Guard**: `(none — zero address unchecked)[token]`
- **Key args**: `token`
- **Missing**: `require(token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `deposit()` — VaultManyArguments.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/synapsecns__sanguine/packages/contracts-rfq/test/mocks/VaultManyArguments.sol`
- **Line**: 14
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_transferInputAsset()` — SynapseIntentRouter.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/synapsecns__sanguine/packages/contracts-rfq/contracts/router/SynapseIntentRouter.sol`
- **Line**: 108
- **Guard**: `(none — zero address unchecked)[token]`
- **Key args**: `token`
- **Missing**: `require(token != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `bridge()` — FastBridgeRouterV2.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/synapsecns__sanguine/packages/contracts-rfq/contracts/legacy/rfq/FastBridgeRouterV2.sol`
- **Line**: 51
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Metis Bridge

Repo: https://github.com/MetisProtocol/mvm

#### `relayMessage()` — L2CrossDomainMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L2/messaging/L2CrossDomainMessenger.sol`
- **Line**: 149
- **Guard**: `relayedMessages[relayId]`
- **Key args**: `xDomainCalldata, msg.sender, block.number`
- **Missing**: `destChainId / block.chainid`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessage()` — L2CrossDomainMessenger.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L2/messaging/L2CrossDomainMessenger.sol`
- **Line**: 105
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_target, _sender, _message, _messageNonce`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20ByChainId()` — L1StandardBridgeLocal.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L1/messaging/L1StandardBridgeLocal.sol`
- **Line**: 234
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20ToByChainId()` — L1StandardBridgeLocal.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L1/messaging/L1StandardBridgeLocal.sol`
- **Line**: 254
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20ByChainId()` — L1StandardBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L1/messaging/L1StandardBridge.sol`
- **Line**: 253
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositERC20ToByChainId()` — L1StandardBridge.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L1/messaging/L1StandardBridge.sol`
- **Line**: 273
- **Guard**: `(none — msg.value unchecked)[_amount]`
- **Key args**: `_amount`
- **Missing**: `require(msg.value == _amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessageViaChainId()` — L1CrossDomainMessenger.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L1/messaging/L1CrossDomainMessenger.sol`
- **Line**: 294
- **Guard**: `relayedMessages[relayId]`
- **Key args**: `xDomainCalldata, msg.sender, block.number`
- **Missing**: `destChainId / block.chainid`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `relayMessageViaChainId()` — L1CrossDomainMessenger.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/MetisProtocol__mvm/packages/contracts/contracts/L1/messaging/L1CrossDomainMessenger.sol`
- **Line**: 250
- **Guard**: `(none — no allowlist)[target]`
- **Key args**: `_chainId, _target, _sender, _message, _messageNonce, _proof`
- **Missing**: `require(allowedTargets[target]) — user-supplied call target not allowlisted`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Lisk Bridge

Repo: https://github.com/LiskHQ/lisk-contracts

#### `mint()` — L2LiskToken.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/LiskHQ__lisk-contracts/src/L2/L2LiskToken.sol`
- **Line**: 86
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `claimHodlerdropRedistribution()` — L2HodlerdropRedistribution.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/LiskHQ__lisk-contracts/src/L2/L2HodlerdropRedistribution.sol`
- **Line**: 229
- **Guard**: `(none — proof not consumed)[proof / leaf]`
- **Key args**: ``
- **Missing**: `usedProofs[keccak256(proof, leaf)] = true — Merkle proof never marked as used, can be replayed`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `claimAirdrop()` — L2Airdrop.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/LiskHQ__lisk-contracts/src/L2/L2Airdrop.sol`
- **Line**: 277
- **Guard**: `(none — proof not consumed)[proof / leaf]`
- **Key args**: ``
- **Missing**: `usedProofs[keccak256(proof, leaf)] = true — Merkle proof never marked as used, can be replayed`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Fuel Bridge

Repo: https://github.com/FuelLabs/fuel-bridge

#### `_deposit()` — FuelERC20GatewayV2.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV2.sol`
- **Line**: 24
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_deposit()` — FuelERC20GatewayV3.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV3.sol`
- **Line**: 27
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `deposit()` — FuelERC20GatewayV4.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV4.sol`
- **Line**: 228
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositWithData()` — FuelERC20GatewayV4.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV4.sol`
- **Line**: 253
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositWithPermit()` — FuelERC20GatewayV4.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV4.sol`
- **Line**: 334
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositWithDataAndPermit()` — FuelERC20GatewayV4.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV4.sol`
- **Line**: 370
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_deposit()` — FuelERC20GatewayV4.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20GatewayV4.sol`
- **Line**: 406
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `deposit()` — FuelERC20Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20Gateway.sol`
- **Line**: 115
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `depositWithData()` — FuelERC20Gateway.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20Gateway.sol`
- **Line**: 139
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_deposit()` — FuelERC20Gateway.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC20Gateway/FuelERC20Gateway.sol`
- **Line**: 199
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_deposit()` — FuelERC721Gateway.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC721Gateway/FuelERC721Gateway.sol`
- **Line**: 194
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `_deposit()` — FuelERC721GatewayV2.sol

- **Severity**: CRITICAL
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/FuelLabs__fuel-bridge/packages/solidity-contracts/contracts/messaging/gateway/FuelERC721Gateway/FuelERC721GatewayV2.sol`
- **Line**: 22
- **Guard**: `(none — zero address unchecked)[tokenAddress]`
- **Key args**: `tokenAddress`
- **Missing**: `require(tokenAddress != address(0)) — safeTransferFrom on address(0) silently succeeds, minting without receiving tokens`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

### Aleph Zero Bridge

Repo: https://github.com/Cardinal-Cryptography/most

#### `mint()` — WrappedToken.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Cardinal-Cryptography__most/eth/contracts/WrappedToken.sol`
- **Line**: 42
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `sendTokenRequest()` — MostL2.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Cardinal-Cryptography__most/eth/contracts/MostL2.sol`
- **Line**: 270
- **Guard**: `(none — msg.value unchecked)[amount]`
- **Key args**: `amount`
- **Missing**: `require(msg.value == amount) — calldata amount not validated against actual ETH sent`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

#### `mint()` — StableSwapLP.sol

- **Severity**: HIGH
- **File**: `/home/kali/.cache/bridge-bug-detector/repos/Cardinal-Cryptography__most/eth/contracts/StableSwap/StableSwapLP.sol`
- **Line**: 25
- **Guard**: `single-key role[onlyRelayer/onlyOwner]`
- **Key args**: ``
- **Missing**: `M-of-N threshold signature verification — single key compromise allows unlimited minting (Ronin $624M, Harmony $100M pattern)`
- **Impact**: Without destination chain in the key, the same fulfillment hash is accepted independently on every destination chain → one source burn can trigger N mints.

## Clean Protocols

| Protocol | Files |
|----------|-------|
| Frax Ferry | 28 |
| Boba Network Bridge | 0 |
| StarkNet L1 Bridge | 8 |
| Superchain WETH | 0 |
| Hashi Bridge | 106 |
| Telepathy Bridge | 50 |
| Electron Labs Bridge | 1 |
| Volt Protocol Bridge | 31 |
| Holograph Bridge | 0 |

## Failed Clones

- Liqwid Cross-chain (https://github.com/FairBlocksTech/pob-bridge)
- zkBridge (https://github.com/rdi-berkeley/zkbridge)
- Celer IM Messaging (https://github.com/celer-network/im-examples)
- Hop Protocol v2 (https://github.com/hop-protocol/contracts-v2)
- Router Nitro (https://github.com/router-protocol/nitro-contracts)