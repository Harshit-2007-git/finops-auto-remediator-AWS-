"""
Configuration module for FinOps Auto-Remediation.

All settings are loaded from environment variables with safe defaults.
No AWS calls are made at import time.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = PROJECT_ROOT / "policies"
PRICES_DIR = PROJECT_ROOT / "prices"


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    """Immutable application configuration loaded from environment variables."""

    # AWS
    region: str = field(
        default_factory=lambda: os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    )

    # Safety
    dry_run: bool = field(
        default_factory=lambda: os.environ.get("DRY_RUN", "true").lower() == "true"
    )
    demo_mode: bool = field(
        default_factory=lambda: os.environ.get("DEMO_MODE", "false").lower() == "true"
    )

    # Scope tags
    scope_tag_key: str = field(
        default_factory=lambda: os.environ.get("SCOPE_TAG_KEY", "Project")
    )
    scope_tag_value: str = field(
        default_factory=lambda: os.environ.get("SCOPE_TAG_VALUE", "finops-demo")
    )

    # EC2 thresholds
    ec2_cpu_threshold: float = field(
        default_factory=lambda: float(os.environ.get("EC2_CPU_THRESHOLD", "5.0"))
    )
    ec2_idle_window_days: int = field(
        default_factory=lambda: int(os.environ.get("EC2_IDLE_WINDOW_DAYS", "7"))
    )

    # EBS thresholds
    ebs_unattached_days: int = field(
        default_factory=lambda: int(os.environ.get("EBS_UNATTACHED_DAYS", "30"))
    )

    # Demo mode thresholds (minutes)
    demo_ec2_idle_minutes: int = field(
        default_factory=lambda: int(os.environ.get("DEMO_EC2_IDLE_MINUTES", "60"))
    )
    demo_ebs_unattached_minutes: int = field(
        default_factory=lambda: int(
            os.environ.get("DEMO_EBS_UNATTACHED_MINUTES", "120")
        )
    )

    # Circuit breaker
    max_remediations_per_run: int = field(
        default_factory=lambda: int(
            os.environ.get("MAX_REMEDIATIONS_PER_RUN", "5")
        )
    )

    # Tenant
    company: str = field(
        default_factory=lambda: os.environ.get("COMPANY", "pixelforge")
    )
    tenant_id: str = field(
        default_factory=lambda: os.environ.get("TENANT_ID", os.environ.get("COMPANY", "pixelforge"))
    )

    # DynamoDB
    audit_table_name: str = field(
        default_factory=lambda: os.environ.get("AUDIT_TABLE_NAME", "finops-audit-log")
    )

    # KMS
    kms_key_alias: str = field(
        default_factory=lambda: os.environ.get("KMS_KEY_ALIAS", "alias/finops-key")
    )

    # SNS
    sns_topic_arn: str = field(
        default_factory=lambda: os.environ.get("SNS_TOPIC_ARN", "")
    )

    # SSM
    hmac_param_name: str = field(
        default_factory=lambda: os.environ.get("HMAC_PARAM_NAME", "/finops/hmac-secret")
    )

    # Approval
    approval_url_base: str = field(
        default_factory=lambda: os.environ.get("APPROVAL_URL_BASE", "")
    )

    # -----------------------------------------------------------------------
    # Derived helpers
    # -----------------------------------------------------------------------
    @property
    def ec2_idle_window_hours(self) -> float:
        """Return the effective EC2 idle window in hours."""
        if self.demo_mode:
            return self.demo_ec2_idle_minutes / 60.0
        return self.ec2_idle_window_days * 24.0

    @property
    def ebs_unattached_hours(self) -> float:
        """Return the effective EBS unattached threshold in hours."""
        if self.demo_mode:
            return self.demo_ebs_unattached_minutes / 60.0
        return self.ebs_unattached_days * 24.0

    @property
    def kms_key_arn(self) -> str:
        """Return KMS key ARN or alias."""
        return os.environ.get("KMS_KEY_ARN", self.kms_key_alias)


# ---------------------------------------------------------------------------
# Company policy loader
# ---------------------------------------------------------------------------
def load_company_policy(company: str) -> dict[str, Any]:
    """Load per-company policy JSON from the policies directory.

    Args:
        company: Company identifier (e.g. 'pixelforge').

    Returns:
        Parsed policy dict. Returns empty dict with defaults if file missing.
    """
    policy_file = POLICIES_DIR / f"{company}.json"
    if not policy_file.exists():
        return {
            "company": company,
            "display_name": company.title(),
            "overrides": {"env_rules": {}},
        }
    with open(policy_file, "r", encoding="utf-8") as f:
        return json.load(f)


def load_prices(region: str | None = None) -> dict[str, Any]:
    """Load pricing data from prices/prices.json.

    Args:
        region: AWS region key. If None, returns all regions.

    Returns:
        Pricing dict for the region, or full pricing dict.
    """
    prices_file = PRICES_DIR / "prices.json"
    with open(prices_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    if region:
        return data.get(region, {})
    return data


# ---------------------------------------------------------------------------
# Module-level singleton (created on first import)
# ---------------------------------------------------------------------------
def get_config() -> Config:
    """Return a Config instance from current environment variables."""
    return Config()
