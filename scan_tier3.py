#!/usr/bin/env python3
"""Run the bridge bug detector against Tier 3 protocol targets."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bridge_detector.scanner.protocols import PROTOCOLS_TIER3
from bridge_detector.scanner.orchestrator import run_mass_scan

run_mass_scan(
    protocols=PROTOCOLS_TIER3,
    output_dir=Path("scan-results-tier3"),
)
