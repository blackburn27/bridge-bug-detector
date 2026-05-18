"""
Curated list of bridge protocols to scan.
Each entry is a Protocol with the GitHub clone URL and the subdirectory
within the repo that contains Solidity source (relative to repo root).
An empty src_path means scan the entire repo.
"""

from dataclasses import dataclass, field


@dataclass
class Protocol:
    name: str
    repo_url: str           # HTTPS clone URL
    src_paths: list[str]    # subdirs to scan; empty list = whole repo
    notes: str = ""


# ---------------------------------------------------------------------------
# Priority tier: actively maintained, large TVL, no KYC wall on disclosures
# ---------------------------------------------------------------------------

PROTOCOLS: list[Protocol] = [
    Protocol(
        name="Across Protocol",
        repo_url="https://github.com/across-protocol/contracts",
        src_paths=["contracts"],
        notes="High TVL, intent-based bridge",
    ),
    Protocol(
        name="Hop Protocol",
        repo_url="https://github.com/hop-protocol/contracts",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Stargate Finance",
        repo_url="https://github.com/stargate-protocol/stargate",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Stargate v2",
        repo_url="https://github.com/stargate-protocol/stargate-v2",
        src_paths=["packages/stg-evm-v2/src"],
    ),
    Protocol(
        name="Connext",
        repo_url="https://github.com/connext/monorepo",
        src_paths=["packages/contracts-core/contracts", "packages/deployments/contracts/contracts"],
    ),
    Protocol(
        name="Synapse Protocol",
        repo_url="https://github.com/synapsecns/synapse-contracts",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Celer cBridge",
        repo_url="https://github.com/celer-network/sgn-v2-contracts",
        src_paths=["contracts"],
    ),
    Protocol(
        name="deBridge",
        repo_url="https://github.com/debridge-finance/debridge-contracts-v1",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Socket / Bungee",
        repo_url="https://github.com/SocketDotTech/socket-DL",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Axelar Gateway",
        repo_url="https://github.com/axelarnetwork/axelar-cgp-solidity",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Hyperlane",
        repo_url="https://github.com/hyperlane-xyz/hyperlane-monorepo",
        src_paths=["solidity/contracts"],
    ),
    Protocol(
        name="Wormhole",
        repo_url="https://github.com/wormhole-foundation/wormhole",
        src_paths=["ethereum/contracts"],
    ),
    Protocol(
        name="Wormhole NTT",
        repo_url="https://github.com/wormhole-foundation/native-token-transfers",
        src_paths=["evm/src"],
    ),
    Protocol(
        name="LayerZero v1",
        repo_url="https://github.com/LayerZero-Labs/LayerZero",
        src_paths=["contracts"],
    ),
    Protocol(
        name="LayerZero v2",
        repo_url="https://github.com/LayerZero-Labs/LayerZero-v2",
        src_paths=["packages/layerzero-v2/evm"],
    ),
    Protocol(
        name="Chainlink CCIP",
        repo_url="https://github.com/smartcontractkit/ccip",
        src_paths=["contracts/src/v0.8"],
    ),
    Protocol(
        name="dln.trade (DLN)",
        repo_url="https://github.com/debridge-finance/dln-contracts",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Router Protocol CrossTalk",
        repo_url="https://github.com/router-protocol/router-crosstalk-openzeppelin-standards",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Li.Fi Contracts",
        repo_url="https://github.com/lifinance/contracts",
        src_paths=["src"],
    ),
    Protocol(
        name="Biconomy Hyphen",
        repo_url="https://github.com/bcnmy/hyphen-contract",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Optimism Standard Bridge",
        repo_url="https://github.com/ethereum-optimism/optimism",
        src_paths=["packages/contracts-bedrock/src/L1", "packages/contracts-bedrock/src/L2"],
    ),
    Protocol(
        name="Arbitrum Bridge",
        repo_url="https://github.com/OffchainLabs/nitro-contracts",
        src_paths=["src"],
    ),
    Protocol(
        name="Polygon zkEVM Bridge",
        repo_url="https://github.com/0xPolygonHermez/zkevm-contracts",
        src_paths=["contracts"],
    ),
    Protocol(
        name="Scroll Bridge",
        repo_url="https://github.com/scroll-tech/scroll",
        src_paths=["scroll-contracts/src", "rollup"],
    ),
    Protocol(
        name="zkSync Bridge",
        repo_url="https://github.com/matter-labs/era-contracts",
        src_paths=["l1-contracts/contracts", "l2-contracts/contracts"],
    ),
]
