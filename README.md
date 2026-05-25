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
