"""
Tests for Audit Log Writer and Reader — Milestone M3.

Covers:
    - Writing audit log entries to DynamoDB
    - Reading and decrypting audit log entries from DynamoDB
    - Verification that sensitive data is encrypted in DynamoDB
    - TTL setting (90 days retention)
    - Error handling for missing records
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
import boto3
import pytest
from moto import mock_aws

from src.audit.writer import read_audit_log, write_audit_log
from src.config import Config
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk


@pytest.fixture
def audit_environment():
    """Set up mock DynamoDB table and KMS key."""
    old_table = os.environ.get("AUDIT_TABLE_NAME")
    old_key = os.environ.get("KMS_KEY_ARN")
    old_region = os.environ.get("AWS_DEFAULT_REGION")
    with mock_aws():
        region = "ap-south-1"
        os.environ["AWS_DEFAULT_REGION"] = region
        os.environ["AUDIT_TABLE_NAME"] = "finops-audit-log-test"

        # Create KMS Key
        kms = boto3.client("kms", region_name=region)
        key = kms.create_key(Description="Audit Test Key")
        key_id = key["KeyMetadata"]["KeyId"]
        os.environ["KMS_KEY_ARN"] = key_id

        # Create DynamoDB Table
        ddb = boto3.client("dynamodb", region_name=region)
        ddb.create_table(
            TableName="finops-audit-log-test",
            KeySchema=[
                {"AttributeName": "tenant_id", "KeyType": "HASH"},
                {"AttributeName": "log_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "tenant_id", "AttributeType": "S"},
                {"AttributeName": "log_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        config = Config()
        yield ddb, kms, key_id, config

    if old_table is not None:
        os.environ["AUDIT_TABLE_NAME"] = old_table
    else:
        os.environ.pop("AUDIT_TABLE_NAME", None)

    if old_key is not None:
        os.environ["KMS_KEY_ARN"] = old_key
    else:
        os.environ.pop("KMS_KEY_ARN", None)

    if old_region is not None:
        os.environ["AWS_DEFAULT_REGION"] = old_region
    else:
        os.environ.pop("AWS_DEFAULT_REGION", None)


class TestAuditWriter:
    """Test audit log writing and reading capabilities."""

    def test_write_and_read_audit_log(self, audit_environment):
        """Writing an audit entry stores it encrypted and reading decrypts it successfully."""
        ddb, kms, key_id, config = audit_environment

        finding = Finding(
            resource_id="i-0abc123456789def0",
            resource_type="ec2",
            idle_duration_hours=72.0,
            avg_cpu=1.2,
            tags={"Name": "dev-db", "Project": "finops-demo", "env": "dev", "owner": "alice@pixelforge.io"},
            estimated_monthly_cost=35.00,
            instance_type="t3.medium",
        )

        evaluation = EvaluationResult(
            finding=finding,
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            decision=Decision.AUTO_REMEDIATE,
            reason="High confidence (0.95), low risk (0.20) dev environment resource.",
        )

        # Write audit record
        result = write_audit_log(
            finding=finding,
            evaluation=evaluation,
            action_taken="AUTO_REMEDIATED",
            config=config,
            dynamodb_client=ddb,
            kms_client=kms,
        )

        log_id = result["log_id"]
        assert log_id is not None

        # Verify DynamoDB row directly
        item_response = ddb.get_item(
            TableName=config.audit_table_name,
            Key={"tenant_id": {"S": "pixelforge"}, "log_id": {"S": log_id}},
        )
        item = item_response["Item"]
        assert item["resource_id"]["S"] == "i-0abc123456789def0"
        assert item["action_taken"]["S"] == "AUTO_REMEDIATED"
        assert item["company"]["S"] == "pixelforge"
        assert item["tenant_id"]["S"] == "pixelforge"
        assert "run_id" in item
        assert "ciphertext_b64" in item
        assert "encrypted_data_key_b64" in item

        # Read back via reader and decrypt
        retrieved = read_audit_log(
            log_id=log_id,
            config=config,
            dynamodb_client=ddb,
            kms_client=kms,
        )

        assert retrieved["log_id"] == log_id
        assert retrieved["resource_id"] == "i-0abc123456789def0"
        assert retrieved["action_taken"] == "AUTO_REMEDIATED"
        assert retrieved["details"]["finding"]["resource_id"] == "i-0abc123456789def0"
        assert retrieved["details"]["evaluation"]["confidence"] == "HIGH"

    def test_ttl_calculation(self, audit_environment):
        """TTL is set approximately 90 days in the future."""
        ddb, kms, key_id, config = audit_environment

        finding = Finding(
            resource_id="vol-01234567",
            resource_type="ebs",
            idle_duration_hours=720.0,
            tags={"Name": "old-vol", "Project": "finops-demo", "env": "dev"},
            estimated_monthly_cost=10.00,
        )
        evaluation = EvaluationResult(
            finding=finding,
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            decision=Decision.AUTO_REMEDIATE,
            reason="Unattached EBS",
        )

        result = write_audit_log(finding, evaluation, "AUTO_REMEDIATED", config, ddb, kms)
        log_id = result["log_id"]

        item = ddb.get_item(
            TableName=config.audit_table_name,
            Key={"tenant_id": {"S": "pixelforge"}, "log_id": {"S": log_id}},
        )["Item"]
        ttl_val = int(item["ttl"]["N"])
        now_val = int(datetime.now(timezone.utc).timestamp())

        # Check TTL is around 90 days (86400 * 90 = 7,776,000 seconds)
        diff_days = (ttl_val - now_val) / 86400.0
        assert 88.0 <= diff_days <= 92.0

    def test_read_non_existent_record_raises(self, audit_environment):
        """Reading a non-existent log_id raises ValueError."""
        ddb, kms, key_id, config = audit_environment

        with pytest.raises(ValueError, match="Audit record not found"):
            read_audit_log("non-existent-uuid", config, ddb, kms)
