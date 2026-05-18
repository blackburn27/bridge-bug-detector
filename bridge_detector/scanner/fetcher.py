"""
Clones bridge protocol repos into a local cache directory.
Uses git clone --depth=1 for speed. Re-uses cached clones on subsequent runs.
"""

import subprocess
import sys
from pathlib import Path

from .protocols import Protocol

_DEFAULT_CACHE = Path.home() / ".cache" / "bridge-bug-detector" / "repos"


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def repo_dir(protocol: Protocol, cache_dir: Path) -> Path:
    """Return the local path where this protocol's repo lives (or will live)."""
    slug = protocol.repo_url.rstrip("/").split("/")[-1]
    owner = protocol.repo_url.rstrip("/").split("/")[-2]
    return cache_dir / f"{owner}__{slug}"


def fetch_protocol(protocol: Protocol, cache_dir: Path, verbose: bool = True) -> Path | None:
    """
    Clone the protocol repo if not already cached.
    Returns the repo root Path on success, None on failure.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    dest = repo_dir(protocol, cache_dir)

    if dest.exists():
        if verbose:
            print(f"  [cache] {protocol.name} → {dest.name}")
        return dest

    if verbose:
        print(f"  [clone] {protocol.name} …", end=" ", flush=True)

    result = _run(["git", "clone", "--depth=1", "--quiet", protocol.repo_url, str(dest)])

    if result.returncode != 0:
        if verbose:
            print(f"FAILED\n         {result.stderr.strip()}")
        return None

    if verbose:
        print("done")
    return dest


def sol_files_for_protocol(protocol: Protocol, repo_root: Path) -> list[Path]:
    """Return all .sol files under the configured src_paths (or entire repo if empty)."""
    search_roots = (
        [repo_root / p for p in protocol.src_paths]
        if protocol.src_paths
        else [repo_root]
    )
    files: list[Path] = []
    for root in search_roots:
        if root.exists():
            files.extend(root.rglob("*.sol"))
        # silently skip missing sub-paths (repo structure may differ from expectation)
    return files


def fetch_all(
    protocols: list[Protocol],
    cache_dir: Path = _DEFAULT_CACHE,
    verbose: bool = True,
) -> list[tuple[Protocol, Path | None]]:
    """
    Fetch all protocols. Returns list of (protocol, repo_root) pairs;
    repo_root is None if the clone failed.
    """
    return [(p, fetch_protocol(p, cache_dir, verbose=verbose)) for p in protocols]
