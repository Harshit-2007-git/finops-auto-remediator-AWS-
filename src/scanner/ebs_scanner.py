"""
EBS Scanner — detects unattached EBS volumes.

Finds volumes in 'available' state (unattached) that have been unattached
longer than the configured threshold.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import boto3

from src.config import Config, get_config
from src.policy_engine import Finding

logger = logging.getLogger(__name__)


def _get_volume_tags(volume: dict[str, Any]) -> dict[str, str]:
    """Extract tags from an EBS volume description into a flat dict."""
    return {tag["Key"]: tag["Value"] for tag in volume.get("Tags", [])}


def _get_volume_name(tags: dict[str, str]) -> str:
    """Get the Name tag value, or 'unnamed'."""
    return tags.get("Name", "unnamed")


# In-memory tracking fallback when DynamoDB is not available
_MEMORY_FIRST_SEEN_CACHE: dict[str, str] = {}


def scan(
    config: Config | None = None,
    ec2_client: Any = None,
    dynamodb_client: Any = None,
) -> list[Finding]:
    """Scan for unattached EBS volumes.

    Steps:
        1. Describe volumes with status=available and the scope tag
        2. For each volume, calculate how long it's been unattached
           using volume tag or platform DynamoDB first-seen tracking
        3. If unattached > threshold → create Finding

    Args:
        config: Application config. Uses get_config() if None.
        ec2_client: boto3 EC2 client. Creates one if None.
        dynamodb_client: boto3 DynamoDB client for platform tracking.

    Returns:
        List of Finding objects for unattached volumes.
    """
    if config is None:
        config = get_config()
    if ec2_client is None:
        ec2_client = boto3.client("ec2", region_name=config.region)

    unattached_hours = config.ebs_unattached_hours

    logger.info(
        "EBS scan: threshold=%.1fh, scope=%s=%s",
        unattached_hours,
        config.scope_tag_key,
        config.scope_tag_value,
    )

    # Step 1: Find available volumes (filtered by scope tag if set)
    filters = [{"Name": "status", "Values": ["available"]}]
    if config.scope_tag_key:
        filters.append({
            "Name": f"tag:{config.scope_tag_key}",
            "Values": [config.scope_tag_value],
        })

    response = ec2_client.describe_volumes(Filters=filters)

    volumes = response.get("Volumes", [])
    logger.info("Found %d available (unattached) volumes in scope", len(volumes))

    # Step 2-3: Check unattached duration
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for volume in volumes:
        volume_id = volume["VolumeId"]
        tags = _get_volume_tags(volume)
        name = _get_volume_name(tags)
        size_gb = volume.get("Size", 1)
        volume_type = volume.get("VolumeType", "gp3")

        first_seen_str = tags.get("FinOpsFirstSeenUnattached")
        is_newly_discovered = False

        if not first_seen_str:
            # Check platform DynamoDB tracking table
            tenant_id = getattr(config, "tenant_id", None) or getattr(config, "company", "pixelforge")
            ddb = dynamodb_client
            if ddb is None:
                try:
                    ddb = boto3.client("dynamodb", region_name=config.region)
                except Exception:
                    ddb = None

            table_name = getattr(config, "audit_table_name", "finops-audit-log")
            state_key = f"first_seen#{volume_id}"

            if ddb is not None:
                try:
                    resp = ddb.get_item(
                        TableName=table_name,
                        Key={"tenant_id": {"S": tenant_id}, "log_id": {"S": state_key}},
                    )
                    if "Item" in resp and "first_seen_at" in resp["Item"]:
                        first_seen_str = resp["Item"]["first_seen_at"]["S"]
                    else:
                        now_iso = now.isoformat()
                        ddb.put_item(
                            TableName=table_name,
                            Item={
                                "tenant_id": {"S": tenant_id},
                                "log_id": {"S": state_key},
                                "volume_id": {"S": volume_id},
                                "first_seen_at": {"S": now_iso},
                            },
                        )
                        first_seen_str = now_iso
                        is_newly_discovered = True
                except Exception as ddb_err:
                    logger.debug("Platform DynamoDB check for volume %s: %s", volume_id, ddb_err)

            if not first_seen_str:
                cache_key = f"{tenant_id}:{volume_id}"
                if cache_key in _MEMORY_FIRST_SEEN_CACHE:
                    first_seen_str = _MEMORY_FIRST_SEEN_CACHE[cache_key]
                else:
                    now_iso = now.isoformat()
                    _MEMORY_FIRST_SEEN_CACHE[cache_key] = now_iso
                    first_seen_str = now_iso
                    is_newly_discovered = True

        if is_newly_discovered:
            try:
                ec2_client.create_tags(
                    Resources=[volume_id],
                    Tags=[{"Key": "FinOpsFirstSeenUnattached", "Value": first_seen_str or now.isoformat()}],
                )
            except Exception as tag_err:
                logger.debug("Optional volume tag creation skipped/denied for %s: %s", volume_id, tag_err)

            logger.info(
                "Volume %s (%s): newly discovered unattached, recorded first seen in platform DynamoDB and skipping",
                volume_id,
                name,
            )
            continue

        try:
            first_seen_dt = datetime.fromisoformat(first_seen_str)
            if first_seen_dt.tzinfo is None:
                first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
            unattached_duration_hours = (now - first_seen_dt).total_seconds() / 3600.0
        except Exception as parse_err:
            logger.warning("Invalid FinOpsFirstSeenUnattached tag on %s (%s): %s", volume_id, first_seen_str, parse_err)
            continue

        if unattached_duration_hours >= unattached_hours:
            # Estimate monthly cost
            from src.config import load_prices

            prices = load_prices(config.region)
            ebs_prices = prices.get("ebs", {})
            type_prices = ebs_prices.get(volume_type, {})
            per_gb_monthly = type_prices.get("per_gb_monthly", 0.08)
            estimated_monthly = per_gb_monthly * size_gb

            finding = Finding(
                resource_id=volume_id,
                resource_type="ebs",
                idle_duration_hours=unattached_duration_hours,
                avg_cpu=None,
                tags=tags,
                estimated_monthly_cost=round(estimated_monthly, 2),
                instance_type=f"{volume_type}/{size_gb}GB",
            )
            findings.append(finding)
            logger.info(
                "UNATTACHED: %s (%s) — %.1fh, %dGB %s, est=$%.2f/mo",
                volume_id,
                name,
                unattached_duration_hours,
                size_gb,
                volume_type,
                estimated_monthly,
            )

    logger.info("EBS scan complete: %d unattached volumes found", len(findings))
    return findings
