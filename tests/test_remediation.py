"""
Tests for Remediation Handler — Milestone M5.

Covers:
    - Stopping EC2 instances and adding FinOps tags
    - Creating snapshot and deleting EBS volumes
    - Dry-run behavior (skips actual modifications)
    - Audit log writing during remediation
"""

from __future__ import annotations

import os
import boto3
import pytest
from moto import mock_aws

from src.config import Config
from src.policy_engine import Finding
from src.remediation.handler import handler, remediate_resource


@pytest.fixture
def remediation_env():
    """Set up mock EC2, KMS, and DynamoDB environment."""
    with mock_aws():
        region = "ap-south-1"
        os.environ["AWS_DEFAULT_REGION"] = region
        os.environ["AUDIT_TABLE_NAME"] = "finops-audit-remediation-test"

        ec2 = boto3.client("ec2", region_name=region)
        kms = boto3.client("kms", region_name=region)
        ddb = boto3.client("dynamodb", region_name=region)

        # Create KMS key
        key = kms.create_key(Description="Remediation Test Key")
        key_id = key["KeyMetadata"]["KeyId"]
        os.environ["KMS_KEY_ARN"] = key_id

        # Create DynamoDB table
        ddb.create_table(
            TableName="finops-audit-remediation-test",
            KeySchema=[{"AttributeName": "log_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "log_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        yield ec2, kms, ddb


class TestRemediation:
    """Test resource remediation logic."""

    def test_remediate_ec2_live_mode(self, remediation_env):
        """In live mode (dry_run=false), EC2 instance is stopped and tagged."""
        ec2, kms, ddb = remediation_env

        # Create running EC2 instance
        resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        instance_id = resp["Instances"][0]["InstanceId"]

        finding = Finding(
            resource_id=instance_id,
            resource_type="ec2",
            idle_duration_hours=168.0,
            avg_cpu=1.0,
            tags={"Project": "finops-demo", "env": "dev"},
        )

        os.environ["DRY_RUN"] = "false"
        config = Config()
        res = remediate_resource(finding, config=config, ec2_client=ec2)

        assert res["status"] == "SUCCESS"
        assert res["dry_run"] is False

        # Verify instance state is stopped
        inst_desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = inst_desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state in ["stopping", "stopped"]

        # Verify tags
        tags = {t["Key"]: t["Value"] for t in inst_desc["Reservations"][0]["Instances"][0]["Tags"]}
        assert tags.get("FinOpsStatus") == "StoppedByFinOps"

    def test_remediate_ebs_live_mode(self, remediation_env):
        """In live mode (dry_run=false), EBS volume is snapshotted and deleted."""
        ec2, kms, ddb = remediation_env

        vol_resp = ec2.create_volume(AvailabilityZone="ap-south-1a", Size=5)
        volume_id = vol_resp["VolumeId"]

        finding = Finding(
            resource_id=volume_id,
            resource_type="ebs",
            idle_duration_hours=720.0,
            tags={"Project": "finops-demo", "env": "dev"},
        )

        os.environ["DRY_RUN"] = "false"
        config = Config()
        res = remediate_resource(finding, config=config, ec2_client=ec2)

        assert res["status"] == "SUCCESS"
        assert "snapshot_id" in res

        # Verify snapshot exists
        snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [volume_id]}])
        assert len(snaps["Snapshots"]) == 1

        # Verify volume is deleted
        with pytest.raises(Exception):
            ec2.describe_volumes(VolumeIds=[volume_id])

    def test_remediate_dry_run_mode(self, remediation_env):
        """In dry_run mode, resource state remains unchanged."""
        ec2, kms, ddb = remediation_env

        resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        instance_id = resp["Instances"][0]["InstanceId"]

        finding = Finding(
            resource_id=instance_id,
            resource_type="ec2",
            idle_duration_hours=168.0,
            tags={"Project": "finops-demo"},
        )

        os.environ["DRY_RUN"] = "true"
        config = Config()
        res = remediate_resource(finding, config=config, ec2_client=ec2)

        assert res["dry_run"] is True
        assert "[DRY RUN]" in res["action_detail"]

        # Instance remains running
        inst_desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = inst_desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state == "running"

    def test_remediation_handler_full_event(self, remediation_env):
        """Remediation Lambda handler processes event payload, stops EC2, and writes audit record."""
        ec2, kms, ddb = remediation_env
        resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        instance_id = resp["Instances"][0]["InstanceId"]

        os.environ["DRY_RUN"] = "false"
        os.environ["DEMO_MODE"] = "true"
        os.environ["DEMO_EC2_IDLE_MINUTES"] = "1"

        event = {
            "findings": [
                {
                    "resource_id": instance_id,
                    "resource_type": "ec2",
                    "idle_duration_hours": 168.0,
                    "avg_cpu": 1.0,
                    "tags": {"Project": "finops-demo", "env": "dev", "owner": "alice@pixelforge.io"},
                    "estimated_monthly_cost": 15.0,
                }
            ]
        }

        res = handler(event)
        assert res["status"] == "COMPLETED"
        assert res["count"] == 1
        assert len(res["results"]) == 1

        # Verify instance was stopped
        inst_desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = inst_desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state in ["stopping", "stopped"]

    def test_remediation_handler_skips_non_remediate_resource(self, remediation_env):
        """Remediation handler re-evaluates policy and skips resource tagged keep=true (C6 regression test)."""
        ec2, kms, ddb = remediation_env
        resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
        instance_id = resp["Instances"][0]["InstanceId"]

        os.environ["DRY_RUN"] = "false"
        # Resource has keep=true tag
        event = {
            "findings": [
                {
                    "resource_id": instance_id,
                    "resource_type": "ec2",
                    "idle_duration_hours": 200.0,
                    "avg_cpu": 1.0,
                    "tags": {"Project": "finops-demo", "env": "dev", "keep": "true"},
                    "estimated_monthly_cost": 15.0,
                }
            ]
        }

        res = handler(event)
        assert res["status"] == "COMPLETED"
        assert res["count"] == 0  # Safely skipped!

        # Verify instance is STILL running
        inst_desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = inst_desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state == "running"

