"""
EC2 Scanner — detects idle EC2 instances.

Queries CloudWatch for CPUUtilization metrics over the configured window.
Instances with average CPU below the threshold for the entire window are
flagged as idle findings.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from src.config import Config, get_config
from src.policy_engine import Finding

logger = logging.getLogger(__name__)


def _get_instance_tags(instance: dict[str, Any]) -> dict[str, str]:
    """Extract tags from an EC2 instance description into a flat dict."""
    return {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}


def _get_instance_name(tags: dict[str, str]) -> str:
    """Get the Name tag value, or 'unnamed'."""
    return tags.get("Name", "unnamed")


def scan(
    config: Config | None = None,
    ec2_client: Any = None,
    cw_client: Any = None,
) -> list[Finding]:
    """Scan for idle EC2 instances.

    Steps:
        1. Describe all running instances tagged with the scope tag
        2. For each instance, query CloudWatch CPUUtilization
        3. If avg CPU < threshold over the idle window → create Finding

    Args:
        config: Application config. Uses get_config() if None.
        ec2_client: boto3 EC2 client. Creates one if None.
        cw_client: boto3 CloudWatch client. Creates one if None.

    Returns:
        List of Finding objects for idle instances.
    """
    if config is None:
        config = get_config()
    if ec2_client is None:
        ec2_client = boto3.client("ec2", region_name=config.region)
    if cw_client is None:
        cw_client = boto3.client("cloudwatch", region_name=config.region)

    idle_window_hours = config.ec2_idle_window_hours
    cpu_threshold = config.ec2_cpu_threshold

    logger.info(
        "EC2 scan: window=%.1fh, cpu_threshold=%.1f%%, scope=%s=%s",
        idle_window_hours,
        cpu_threshold,
        config.scope_tag_key,
        config.scope_tag_value,
    )

    # Step 1: Find running instances (filtered by scope tag if set)
    filters = [{"Name": "instance-state-name", "Values": ["running"]}]
    if config.scope_tag_key:
        filters.append({
            "Name": f"tag:{config.scope_tag_key}",
            "Values": [config.scope_tag_value],
        })

    response = ec2_client.describe_instances(Filters=filters)

    instances = []
    for reservation in response.get("Reservations", []):
        instances.extend(reservation.get("Instances", []))

    logger.info("Found %d running instances in scope", len(instances))

    # Step 2-3: Check CPU metrics for each instance
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    if config.demo_mode:
        lookback_seconds = max(5 * 3600, int(idle_window_hours * 3600))
    else:
        lookback_seconds = max(60, int(idle_window_hours * 3600))
    start_time = now - timedelta(seconds=lookback_seconds)

    for instance in instances:
        instance_id = instance["InstanceId"]
        tags = _get_instance_tags(instance)
        name = _get_instance_name(tags)
        instance_type = instance.get("InstanceType", "t3.micro")

        # Query CloudWatch for average CPU
        # Period must be >= 60 seconds; clamp to avoid validation errors
        period_seconds = lookback_seconds
        metric_response = cw_client.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=now,
            Period=period_seconds,  # Single period = entire window
            Statistics=["Average"],
        )

        datapoints = metric_response.get("Datapoints", [])

        if not datapoints:
            # Missing CloudWatch CPU data -> treat as skip (insufficient/ambiguous data)
            logger.info(
                "Instance %s (%s): no CloudWatch CPU data, skipping (insufficient/ambiguous data)",
                instance_id,
                name,
            )
            continue

        avg_cpu = sum(dp["Average"] for dp in datapoints) / len(datapoints)
        logger.info(
            "Instance %s (%s): avg_cpu=%.2f%%",
            instance_id,
            name,
            avg_cpu,
        )

        # Check network signal alongside CPU (NetworkIn + NetworkOut)
        net_in_resp = cw_client.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="NetworkIn",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=now,
            Period=period_seconds,
            Statistics=["Average"],
        )
        net_out_resp = cw_client.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="NetworkOut",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start_time,
            EndTime=now,
            Period=period_seconds,
            Statistics=["Average"],
        )
        net_in_dp = net_in_resp.get("Datapoints", [])
        net_out_dp = net_out_resp.get("Datapoints", [])
        avg_net_in = sum(dp["Average"] for dp in net_in_dp) / len(net_in_dp) if net_in_dp else 0.0
        avg_net_out = sum(dp["Average"] for dp in net_out_dp) / len(net_out_dp) if net_out_dp else 0.0
        avg_network_bytes = avg_net_in + avg_net_out

        if avg_network_bytes >= 50000.0:
            logger.info(
                "Instance %s (%s): active network traffic detected (avg=%.1f bytes), skipping",
                instance_id,
                name,
                avg_network_bytes,
            )
            continue

        if avg_cpu < cpu_threshold:
            # Measure idle duration from CloudWatch metric history rather than launch time
            oldest_dp = min(dp["Timestamp"] for dp in datapoints)
            if isinstance(oldest_dp, str):
                oldest_dp = datetime.fromisoformat(oldest_dp)
            if oldest_dp.tzinfo is None:
                oldest_dp = oldest_dp.replace(tzinfo=timezone.utc)

            idle_hours = (now - oldest_dp).total_seconds() / 3600.0
            if len(datapoints) == 1 and idle_hours < (lookback_seconds / 3600.0):
                idle_hours = max(idle_hours, lookback_seconds / 3600.0)

            # Estimate monthly cost
            from src.config import load_prices

            prices = load_prices(config.region)
            ec2_prices = prices.get("ec2", {})
            type_prices = ec2_prices.get(instance_type, {})
            hourly_rate = type_prices.get("on_demand_hourly", 0.0104)
            estimated_monthly = hourly_rate * 730  # avg hours/month

            finding = Finding(
                resource_id=instance_id,
                resource_type="ec2",
                idle_duration_hours=idle_hours,
                avg_cpu=avg_cpu,
                tags=tags,
                estimated_monthly_cost=round(estimated_monthly, 2),
                instance_type=instance_type,
            )
            findings.append(finding)
            logger.info(
                "IDLE: %s (%s) — cpu=%.2f%%, idle=%.1fh, est=$%.2f/mo",
                instance_id,
                name,
                avg_cpu,
                idle_hours,
                estimated_monthly,
            )

    logger.info("EC2 scan complete: %d idle instances found", len(findings))
    return findings
