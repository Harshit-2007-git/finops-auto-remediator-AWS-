#!/usr/bin/env python3
"""
Seed script — creates the canonical 8 demo AWS resources for PixelForge Studios.

Resources seeded:
    - dev-api-01 (t3.micro, idle, CPU 1.0%) -> AUTO_REMEDIATE
    - qa-runner-01 (t3.micro, idle, CPU 2.0%) -> AUTO_REMEDIATE
    - qa-loadtest-02 (t3.micro, idle, keep=true) -> LOG_ONLY
    - prod-report-01 (t3.micro, idle, CPU 0.8%) -> ESCALATE
    - prod-api-01 (t3.micro, busy, CPU 85.0%) -> UNTOUCHED
    - vol-dev-orphan (1 GB gp3, unattached) -> AUTO_REMEDIATE
    - vol-prod-orphan (1 GB gp3, unattached) -> ESCALATE
    - vol-prod-data (1 GB gp3, attached to prod-api-01) -> UNTOUCHED
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Ensure project root is on path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from demo.demo_scenario import seed_canonical_scenario

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def seed_environment(region: str = "ap-south-1", is_mock: bool = False):
    """Seed the canonical 8-resource scenario."""
    logger.info("Seeding PixelForge Studios canonical infrastructure in region %s...", region)
    res = seed_canonical_scenario(region=region, is_mock=is_mock)
    logger.info(
        "Seeding complete: %d instances (%s), %d volumes (%s)",
        len(res["instances"]),
        list(res["instances"].keys()),
        len(res["volumes"]),
        list(res["volumes"].keys()),
    )
    return res


if __name__ == "__main__":
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    seed_environment(region=region, is_mock=False)
