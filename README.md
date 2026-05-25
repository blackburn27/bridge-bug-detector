# Bridge Bug Detector

Static analysis tool for detecting incomplete idempotency keys in cross-chain bridge contracts — the root cause behind billions of dollars in bridge exploits.

Built from a real [HackerOne High severity finding (CC-1)](https://hackerone.com/reports/3739970) in Ripio's bridge contracts.

## What it detects

### CC-1 — Missing destination chain in idempotency key
Bridge fulfillment functions use `keccak256(abi.encodePacked(...))` as a replay guard, but omit `block.chainid` from the key. Since replay guard mappings are chain-local storage, the same fulfillment hash is accepted independently on every destination chain — one source-chain burn triggers N mints.

**Found in the wild**: Ripio `BridgeDeposit.sol`, Celer `PeggedBrc20Bridge.sol`, Brevis `PegBridge.sol`

### CC-2 — Missing source-tx idempotency guard
Bridge mint functions accept a source-chain transaction identifier (`txid`, `nonce`, `refId`, etc.) as a parameter but never store it in a mapping — the identifier is only emitted in an event. The same txid can be submitted unlimited times to mint unbacked tokens.

**Found in the wild**: Adshares `WrappedADS` ([$628K exploit, 2023](https://cryptoadventure.com/adshares-bridge-exploit-drains-about-628k-after-fake-wads-mint/))

### CC-3 — Missing chain ID in off-chain signature digest
Bridge mint functions verify an off-chain ECDSA signature but omit `block.chainid` from the signed message hash. A signature produced for Chain A is cryptographically valid on Chain B (same contract address, same signer). Safe if the contract inherits OZ EIP-712 (chain ID baked into the domain separator).

**Found in the wild**: Multiple mint-by-signature bridges across Tier 2–3 protocols

### CC-4 — ecrecover return value not checked against address(0)
`ecrecover()` returns `address(0)` for any invalid or malformed signature. If `trustedSigner` is uninitialised (Solidity default: `address(0)`), or is ever zeroed out, any garbage signature passes verification. Safe if using `ECDSA.recover()` from OpenZeppelin (reverts internally on null address).

**Found in the wild**: Root cause pattern behind several bridge key-rotation bugs

### CC-5 — Missing source chain / source contract validation in message handlers
Bridge message handlers receive `srcChainId` and `srcAddress` as parameters but never validate them before processing the payload. An attacker can craft a message from an untrusted chain or impersonate a trusted bridge contract from a different chain to trigger arbitrary minting or transfers.

**Found in the wild**: Celer IM `executeMessage`, LayerZero `lzReceive` implementations without `trustedRemote` checks

### CC-6 — Unvalidated external call with user-supplied calldata (calldata injection)
Bridge routers forward user-supplied `target` addresses and `calldata` via `.call()` without allowlisting `target`. Users who approved the router for ERC20 spend are at risk — attackers pass `target = USDC`, `payload = transferFrom(victim, attacker, MAX)` to drain all approvals.

**Found in the wild**: Socket Protocol [$3.3M exploit, Jan 2024](https://rekt.news/socket-rekt/)

### CC-7 — msg.value vs calldata amount mismatch in native token bridge deposits
Payable bridge deposit functions branch on token type. In the native-ETH branch, `amount` from calldata is credited instead of `msg.value`. An attacker sends 0 ETH but sets `amount` to an arbitrary value, crediting themselves a large position on the destination chain.

**Found in the wild**: Meter Bridge [$4.3M exploit, 2022](https://rekt.news/meter-rekt/)

### CC-8 — Merkle proof accepted but not consumed (proof replay)
Merkle-proof bridges verify a leaf against an attested root but never mark the proof or leaf as used. The same valid proof can be submitted repeatedly to drain the bridge.

**Found in the wild**: BNB Bridge [$586M exploit, 2022](https://rekt.news/bnb-bridge-rekt/), Hyperbridge (2026)

### CC-9 — safeTransferFrom on user-supplied token address without zero-address guard
When `tokenAddress` is `address(0)`, `IERC20(address(0)).safeTransferFrom(...)` targets the zero address (an EOA), returns empty bytes, and OZ's `SafeERC20` interprets the empty return as success — crediting the caller without receiving any tokens.

**Found in the wild**: Qubit Finance [$80M exploit, 2022](https://rekt.news/qubit-rekt/)

### CC-10 — Single-role privileged mint with no threshold signature verification
The bridge mint/release function is guarded only by `onlyOwner` / `onlyRelayer` backed by a single private key. A single key compromise allows unlimited token printing with no cryptographic proof of a corresponding source-chain burn.

**Found in the wild**: Ronin [$624M, 2022](https://rekt.news/ronin-rekt/), Harmony [$100M, 2022](https://rekt.news/harmony-rekt/), Multichain [$130M, 2023](https://rekt.news/multichain-rekt/)

## Mass scan results — 65 protocols, 5,000+ Solidity files

| Finding | Protocol | File | Severity |
|---------|----------|------|----------|
| CC-1 | Celer cBridge | `PeggedBrc20Bridge.sol` | **HIGH** |
| CC-1 | Brevis Network | `PegBridge.sol` | **HIGH** |

All other protocols scanned clean or use trusted-caller architectures (LayerZero, Axelar, Wormhole) that delegate replay protection to the messaging endpoint.

Scans are organized in four tiers by protocol TVL and audit coverage:
- **Tier 1–2** (25 protocols): Across, Hop, Stargate, Connext, Synapse, Celer, LayerZero, Chainlink CCIP, Wormhole, Arbitrum, zkSync, Polygon, Optimism, and more
- **Tier 3** (20 protocols): Gnosis Omnibridge/AMB, Taiko, Linea, Blast, zkLink Nova, Sygma, XY Finance, Rango, Gravity Bridge, Kroma, and more
- **Tier 4** (20 protocols): Scroll, Frax Ferry, Metis, Boba, StarkNet L1, Lisk, Hashi, Telepathy, Holograph, Router Nitro, and more

## Installation

```bash
git clone https://github.com/blackburn27/bridge-bug-detector
cd bridge-bug-detector
pip install -e .
```

## Usage

**Scan a single file:**
```bash
bridge-detect path/to/Bridge.sol
```

**Scan a directory:**
```bash
bridge-detect path/to/contracts/
```

**JSON output:**
```bash
bridge-detect path/to/contracts/ --json
```

**Mass scan all 25 built-in protocols:**
```bash
bridge-detect --mass-scan
```

## Example output

```
[HIGH][CC-1] contracts/pegged-bridge/PeggedBrc20Bridge.sol:71
  Function : mint()
  Guard    : records[mintId]
  Key args : _receiver, _token, _amount, _depositor, _refChainId, _refId, address(this)
  Missing  : block.chainid
  Impact   : Incomplete key → same fulfillment accepted on every dest chain → multi-mint

[HIGH][CC-2] WrappedADS.sol:12
  Function : wrapTo()
  Guard    : (none — missing)
  Key args : uint64 txid
  Missing  : mapping storing txid to prevent replay
  Impact   : No txid guard → same source tx replayed unlimited times → unbacked mint
```

## How it works

1. **Parses Solidity** without a compiler — regex + paren-depth tracking to extract functions, encoded keys, and replay guard mappings
2. **CC-1 check**: finds `mapping[keccak256(abi.encodePacked(...))]` guards and verifies `block.chainid` or a `destChainId` parameter is in the packed arguments
3. **CC-2 check**: finds bridge mint functions that accept txid-like parameters and checks whether those parameters are ever used as a mapping key
4. **Trusted-caller detection**: downgrade to INFORMATIONAL when replay protection is delegated to a trusted messaging endpoint (LayerZero, Axelar, etc.)

## Bug classes

| Rule | Name | Impact |
|------|------|--------|
| CC-1 | Missing dest chain in idempotency key | 1 burn → N mints across all chains |
| CC-2 | Missing source-tx idempotency guard | Unlimited replay of same source tx |

## Disclosures

- **Ripio** (HackerOne #3739970) — CC-1 in `BridgeDeposit.sol`, CVSS 8.9, submitted 2026-05-18 · marked Informational by program
- **Celer cBridge** (GitHub Security Advisory) — CC-1 in `PeggedBrc20Bridge.sol`, submitted 2026-05-18
- **Brevis Network** (GitHub Security Advisory) — CC-1 in `PegBridge.sol`, submitted 2026-05-18 · goodwill disclosure, no bounty program

---

*Reporter: Prameya Singh Soni · [infosecblack.xyz](https://infosecblack.xyz)*
