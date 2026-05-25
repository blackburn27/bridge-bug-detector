#!/usr/bin/env python3
"""Run the bridge bug detector against Tier 4 protocol targets — newer/smaller bridges."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bridge_detector.scanner.protocols import Protocol
from bridge_detector.scanner.orchestrator import run_mass_scan

PROTOCOLS_TIER4 = [
    Protocol(
        name="Scroll Bridge Contracts",
        repo_url="https://github.com/scroll-tech/scroll-contracts",
        src_paths=["src"],
        notes="Scroll L2 bridge — separate repo from main monorepo",
    ),
    Protocol(
        name="Synapse Messaging",
        repo_url="https://github.com/synapsecns/sanguine",
        src_paths=["packages/contracts-rfq", "packages/contracts-communication"],
        notes="Newer Synapse RFQ + messaging contracts",
    ),
    Protocol(
        name="Frax Ferry",
        repo_url="https://github.com/FraxFinance/frax-standard-solidity",
        src_paths=["src"],
        notes="Frax cross-chain bridge",
    ),
    Protocol(
        name="Metis Bridge",
        repo_url="https://github.com/MetisProtocol/mvm",
        src_paths=["packages/contracts/contracts"],
        notes="Metis L2 bridge contracts",
    ),
    Protocol(
        name="Boba Network Bridge",
        repo_url="https://github.com/bobanetwork/boba",
        src_paths=["packages/contracts/contracts"],
        notes="Boba L2 bridge, OP-stack fork with custom extensions",
    ),
    Protocol(
        name="StarkNet L1 Bridge",
        repo_url="https://github.com/starkware-libs/cairo-lang",
        src_paths=["src/starkware/starknet/solidity"],
        notes="StarkNet Ethereum-side bridge contracts",
    ),
    Protocol(
        name="Lisk Bridge",
        repo_url="https://github.com/LiskHQ/lisk-contracts",
        src_paths=["src"],
        notes="Lisk L2 bridge; earlier version flagged CC-8 FP",
    ),
    Protocol(
        name="Superchain WETH",
        repo_url="https://github.com/ethereum-optimism/superchain-ops",
        src_paths=["lib"],
        notes="Superchain WETH and bridge upgrades",
    ),
    Protocol(
        name="Fuel Bridge",
        repo_url="https://github.com/FuelLabs/fuel-bridge",
        src_paths=["packages/solidity-contracts/contracts"],
        notes="Fuel L2 Ethereum-side bridge",
    ),
    Protocol(
        name="Aleph Zero Bridge",
        repo_url="https://github.com/Cardinal-Cryptography/most",
        src_paths=["eth/contracts"],
        notes="Aleph Zero cross-chain bridge, smaller protocol",
    ),
    Protocol(
        name="Liqwid Cross-chain",
        repo_url="https://github.com/FairBlocksTech/pob-bridge",
        src_paths=["contracts"],
        notes="Smaller cross-chain bridge protocol",
    ),
    Protocol(
        name="Hashi Bridge",
        repo_url="https://github.com/gnosis/hashi",
        src_paths=["packages/evm/contracts"],
        notes="Gnosis cross-chain oracle aggregator + bridge",
    ),
    Protocol(
        name="Telepathy Bridge",
        repo_url="https://github.com/succinctlabs/telepathy-contracts",
        src_paths=["src"],
        notes="Succinct ZK bridge; zero-knowledge cross-chain",
    ),
    Protocol(
        name="Electron Labs Bridge",
        repo_url="https://github.com/Electron-Labs/ed25519-circom",
        src_paths=["contracts"],
        notes="ZK bridge verifier contracts",
    ),
    Protocol(
        name="zkBridge",
        repo_url="https://github.com/rdi-berkeley/zkbridge",
        src_paths=["contracts"],
        notes="Berkeley zkBridge research implementation",
    ),
    Protocol(
        name="Volt Protocol Bridge",
        repo_url="https://github.com/volt-protocol/ethereum-credit-guild",
        src_paths=["src"],
        notes="Cross-chain credit guild protocol",
    ),
    Protocol(
        name="Celer IM Messaging",
        repo_url="https://github.com/celer-network/im-examples",
        src_paths=["contracts"],
        notes="Celer IM example cross-chain message contracts",
    ),
    Protocol(
        name="Hop Protocol v2",
        repo_url="https://github.com/hop-protocol/contracts-v2",
        src_paths=["contracts"],
        notes="Hop Protocol v2 updated bridge contracts",
    ),
    Protocol(
        name="Holograph Bridge",
        repo_url="https://github.com/holographxyz/holograph-protocol",
        src_paths=["contracts"],
        notes="Cross-chain NFT bridge and protocol",
    ),
    Protocol(
        name="Router Nitro",
        repo_url="https://github.com/router-protocol/nitro-contracts",
        src_paths=["contracts"],
        notes="Router Protocol Nitro cross-chain bridge",
    ),
]

run_mass_scan(
    protocols=PROTOCOLS_TIER4,
    output_dir=Path("scan-results-tier4"),
)
