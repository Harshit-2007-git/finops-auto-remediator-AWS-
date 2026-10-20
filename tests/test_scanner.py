"""
Tests for the Scanner — Milestone M2.

Covers:
    - Idle EC2 detection (low CPU metrics)
    - Busy EC2 not detected (high CPU metrics)
    - Unattached EBS volume detection
    - Attached EBS volume not detected
    - Untagged resources ignored (scope filter)
    - Demo mode threshold overrides
    - Full scanner handler integration test
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from src.config import Config
from src.scanner import ec2_scanner, ebs_scanner
from src.scanner.app import handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _create_instance(
    ec2_client,
    name: str,
    env: str = "dev",
    project: str = "finops-demo",
    owner: str = "alice@pixelforge.io",
    keep: str | None = None,
    instance_type: str = "t3.micro",
) -> str:
    """Create a tagged running EC2 instance, return instance_id."""
    tags = [
        {"Key": "Name", "Value": name},
        {"Key": "Project", "Value": project},
        {"Key": "env", "Value": env},
        {"Key": "owner", "Value": owner},
    ]
    if keep:
        tags.append({"Key": "keep", "Value": keep})

    resp = ec2_client.run_instances(
        ImageId="ami-12345678",
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
    )
    return resp["Instances"][0]["InstanceId"]


def _put_cpu_metric(cw_client, instance_id: str, avg_cpu: float, hours_ago: float = 0.0):
    """Seed a CloudWatch CPUUtilization metric data point."""
    timestamp = datetime.now(timezone.utc) - timedelta(seconds=30) - timedelta(hours=hours_ago)
    cw_client.put_metric_data(
        Namespace="AWS/EC2",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                "Timestamp": timestamp,
                "Value": avg_cpu,
                "Unit": "Percent",
            }
        ],
    )


def _create_volume(
    ec2_client,
    name: str,
    env: str = "dev",
    project: str = "finops-demo",
    owner: str = "alice@pixelforge.io",
    size_gb: int = 1,
    unattached_hours_ago: float | None = 5.0,
) -> str:
    """Create a tagged EBS volume (unattached), return volume_id."""
    tags = [
        {"Key": "Name", "Value": name},
        {"Key": "Project", "Value": project},
        {"Key": "env", "Value": env},
        {"Key": "owner", "Value": owner},
    ]
    if unattached_hours_ago is not None:
        first_seen = datetime.now(timezone.utc) - timedelta(hours=unattached_hours_ago)
        tags.append({"Key": "FinOpsFirstSeenUnattached", "Value": first_seen.isoformat()})

    resp = ec2_client.create_volume(
        AvailabilityZone="ap-south-1a",
        Size=size_gb,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": tags,
            }
        ],
    )
    return resp["VolumeId"]


def _make_config(**overrides) -> Config:
    """Create a Config with test defaults, applying overrides."""
    # Set env vars for config
    env_defaults = {
        "AWS_DEFAULT_REGION": "ap-south-1",
        "DRY_RUN": "true",
        "DEMO_MODE": "false",
        "EC2_CPU_THRESHOLD": "5.0",
        "EC2_IDLE_WINDOW_DAYS": "7",
        "EBS_UNATTACHED_DAYS": "30",
        "DEMO_EC2_IDLE_MINUTES": "60",
        "DEMO_EBS_UNATTACHED_MINUTES": "120",
        "MAX_REMEDIATIONS_PER_RUN": "5",
        "COMPANY": "pixelforge",
    }
    env_defaults.update(overrides)
    for k, v in env_defaults.items():
        os.environ[k] = v
    return Config()


# ===================================================================
# EC2 Scanner Tests
# ===================================================================
class TestEC2Scanner:
    """Test EC2 idle instance detection."""

    @mock_aws
    def test_idle_ec2_detected(self):
        """EC2 instance with low CPU should be detected as idle."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        instance_id = _create_instance(ec2, "dev-api-01", env="dev")
        _put_cpu_metric(cw, instance_id, avg_cpu=2.0)

        config = _make_config()
        findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

        assert len(findings) == 1
        assert findings[0].resource_id == instance_id
        assert findings[0].resource_type == "ec2"
        assert findings[0].avg_cpu < 5.0

    @mock_aws
    def test_busy_ec2_not_detected(self):
        """EC2 instance with high CPU should NOT be detected."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        instance_id = _create_instance(ec2, "prod-api-01", env="prod")
        _put_cpu_metric(cw, instance_id, avg_cpu=75.0)

        config = _make_config()
        findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

        assert len(findings) == 0

    @mock_aws
    def test_no_metrics_treated_as_skip_not_idle(self):
        """EC2 instance with no CloudWatch data is skipped (ambiguous/missing metrics)."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        _create_instance(ec2, "orphan-instance", env="dev")

        config = _make_config()
        findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

        # No metrics -> skipped, never assumed idle
        assert len(findings) == 0

    @mock_aws
    def test_ec2_high_network_traffic_not_idle(self):
        """EC2 instance with low CPU but active network traffic is NOT detected as idle."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        instance_id = _create_instance(ec2, "proxy-instance", env="dev")
        _put_cpu_metric(cw, instance_id, avg_cpu=1.0)

        # Seed high network throughput (>= 50000 bytes)
        now = datetime.now(timezone.utc)
        cw.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[
                {
                    "MetricName": "NetworkIn",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    "Timestamp": now - timedelta(seconds=30),
                    "Value": 30000.0,
                    "Unit": "Bytes",
                },
                {
                    "MetricName": "NetworkOut",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    "Timestamp": now - timedelta(seconds=30),
                    "Value": 30000.0,
                    "Unit": "Bytes",
                },
            ],
        )

        config = _make_config()
        findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

        assert len(findings) == 0

    @mock_aws
    def test_untagged_ec2_ignored(self):
        """EC2 instances without Project=finops-demo are NOT scanned."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        # Create instance with different project tag
        _create_instance(ec2, "other-instance", project="other-project")

        config = _make_config()
        findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

        assert len(findings) == 0

    @mock_aws
    def test_multiple_instances(self):
        """Scanner handles multiple instances correctly."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        id1 = _create_instance(ec2, "idle-1", env="dev")
        id2 = _create_instance(ec2, "idle-2", env="qa")
        id3 = _create_instance(ec2, "busy-1", env="dev")

        _put_cpu_metric(cw, id1, avg_cpu=1.0)
        _put_cpu_metric(cw, id2, avg_cpu=3.0)
        _put_cpu_metric(cw, id3, avg_cpu=80.0)  # busy

        config = _make_config()
        findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

        assert len(findings) == 2
        found_ids = {f.resource_id for f in findings}
        assert id1 in found_ids
        assert id2 in found_ids
        assert id3 not in found_ids


# ===================================================================
# EBS Scanner Tests
# ===================================================================
class TestEBSScanner:
    """Test EBS unattached volume detection."""

    @mock_aws
    def test_unattached_ebs_detected(self):
        """Unattached EBS volume older than threshold is detected."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")

        volume_id = _create_volume(ec2, "vol-dev-orphan", env="dev", unattached_hours_ago=5.0)

        # Use demo mode with short threshold so volume age exceeds it
        config = _make_config(DEMO_MODE="true", DEMO_EBS_UNATTACHED_MINUTES="0")
        findings = ebs_scanner.scan(config=config, ec2_client=ec2)

        assert len(findings) == 1
        assert findings[0].resource_id == volume_id
        assert findings[0].resource_type == "ebs"

    @mock_aws
    def test_ebs_first_seen_unattached_tag_tracking(self):
        """New unattached volume is tagged with FinOpsFirstSeenUnattached and skipped on first run."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")

        # Create volume without FinOpsFirstSeenUnattached tag
        volume_id = _create_volume(ec2, "brand-new-orphan", env="dev", unattached_hours_ago=None)

        config = _make_config(DEMO_MODE="true", DEMO_EBS_UNATTACHED_MINUTES="0")

        # First scan: volume should be skipped and tagged
        findings = ebs_scanner.scan(config=config, ec2_client=ec2)
        assert len(findings) == 0

        # Verify tag was added to volume in EC2
        desc = ec2.describe_volumes(VolumeIds=[volume_id])
        tags = {t["Key"]: t["Value"] for t in desc["Volumes"][0].get("Tags", [])}
        assert "FinOpsFirstSeenUnattached" in tags

    @mock_aws
    def test_attached_ebs_not_detected(self):
        """Attached (in-use) EBS volumes should NOT be detected."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")

        # Create an instance to attach volume to
        instance_id = _create_instance(ec2, "host-instance", env="dev")
        volume_id = _create_volume(ec2, "vol-attached", env="dev", unattached_hours_ago=5.0)

        # Attach volume to instance
        ec2.attach_volume(
            VolumeId=volume_id,
            InstanceId=instance_id,
            Device="/dev/sdf",
        )

        config = _make_config(DEMO_MODE="true", DEMO_EBS_UNATTACHED_MINUTES="0")
        findings = ebs_scanner.scan(config=config, ec2_client=ec2)

        # The volume is now 'in-use', not 'available'
        assert len(findings) == 0

    @mock_aws
    def test_untagged_ebs_ignored(self):
        """EBS volumes without Project=finops-demo are NOT scanned."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")

        _create_volume(ec2, "other-vol", project="other-project", unattached_hours_ago=5.0)

        config = _make_config(DEMO_MODE="true", DEMO_EBS_UNATTACHED_MINUTES="0")
        findings = ebs_scanner.scan(config=config, ec2_client=ec2)

        assert len(findings) == 0

    @mock_aws
    def test_young_volume_not_detected(self):
        """Recently created volume below threshold is NOT detected."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")

        _create_volume(ec2, "new-volume", env="dev", unattached_hours_ago=0.5)

        # Use production defaults (30 days threshold) — volume is brand new
        config = _make_config(DEMO_MODE="false")
        findings = ebs_scanner.scan(config=config, ec2_client=ec2)

        assert len(findings) == 0


# ===================================================================
# Demo Mode Tests
# ===================================================================
class TestDemoMode:
    """Test that demo mode uses shorter thresholds."""

    @mock_aws
    def test_demo_mode_ec2_thresholds(self):
        """DEMO_MODE=true uses 60-minute EC2 idle window."""
        config = _make_config(DEMO_MODE="true")
        assert config.demo_mode is True
        assert config.ec2_idle_window_hours == 1.0  # 60 min = 1 hour

    @mock_aws
    def test_demo_mode_ebs_thresholds(self):
        """DEMO_MODE=true uses 120-minute EBS threshold."""
        config = _make_config(DEMO_MODE="true")
        assert config.ebs_unattached_hours == 2.0  # 120 min = 2 hours

    @mock_aws
    def test_production_mode_thresholds(self):
        """DEMO_MODE=false uses 7-day EC2 and 30-day EBS thresholds."""
        config = _make_config(DEMO_MODE="false")
        assert config.demo_mode is False
        assert config.ec2_idle_window_hours == 168.0  # 7 * 24
        assert config.ebs_unattached_hours == 720.0  # 30 * 24


# ===================================================================
# Integration Test
# ===================================================================
class TestScannerHandlerIntegration:
    """Test the full scanner handler end-to-end."""

    @mock_aws
    def test_scanner_handler_full_run(self):
        """Full scanner run with mixed idle/busy resources."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        # Create resources
        idle_id = _create_instance(ec2, "dev-idle", env="dev")
        busy_id = _create_instance(ec2, "dev-busy", env="dev")
        _put_cpu_metric(cw, idle_id, avg_cpu=1.0)
        _put_cpu_metric(cw, busy_id, avg_cpu=80.0)

        vol_id = _create_volume(ec2, "orphan-vol", env="dev")

        # Use demo mode with very short thresholds
        config = _make_config(
            DEMO_MODE="true",
            DEMO_EBS_UNATTACHED_MINUTES="0",
            DEMO_EC2_IDLE_MINUTES="0",
        )

        # Directly call the individual scanners with injected clients
        ec2_findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)
        ebs_findings = ebs_scanner.scan(config=config, ec2_client=ec2)

        # Verify EC2 findings
        assert len(ec2_findings) >= 1
        ec2_ids = {f.resource_id for f in ec2_findings}
        assert idle_id in ec2_ids
        assert busy_id not in ec2_ids

        # Verify EBS findings
        assert len(ebs_findings) >= 1
        ebs_ids = {f.resource_id for f in ebs_findings}
        assert vol_id in ebs_ids

    @mock_aws
    def test_handler_returns_summary(self):
        """Handler returns proper summary structure when given clients."""
        ec2 = boto3.client("ec2", region_name="ap-south-1")
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        _create_instance(ec2, "dev-test", env="dev")

        os.environ["DEMO_MODE"] = "true"
        os.environ["DEMO_EC2_IDLE_MINUTES"] = "1"
        os.environ["DEMO_EBS_UNATTACHED_MINUTES"] = "1"

        # Patch boto3.client inside the scanner modules to return mocked clients
        def mock_client_factory(service, **kwargs):
            if service == "ec2":
                return ec2
            if service == "cloudwatch":
                return cw
            return boto3.client(service, **kwargs)

        with patch("src.scanner.ec2_scanner.boto3.client", side_effect=mock_client_factory), \
             patch("src.scanner.ebs_scanner.boto3.client", side_effect=mock_client_factory):
            result = handler({}, None)

        assert "run_id" in result
        assert "counts" in result
        assert "results" in result
        assert "dry_run" in result
        assert "estimated_monthly_savings" in result
        assert result["company"] == "pixelforge"
