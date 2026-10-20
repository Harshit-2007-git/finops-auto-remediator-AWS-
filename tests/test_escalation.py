"""
Tests for Escalation Handler — Milestone M5.

Covers:
    - HMAC signature generation and verification
    - Expired token detection
    - Tampered token detection
    - SNS escalation notification publishing and audit logging
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
import boto3
import pytest
from moto import mock_aws

from src.config import Config
from src.escalation.handler import (
    generate_approval_token,
    get_hmac_secret,
    handler,
    send_escalation_notification,
    verify_approval_token,
)
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk


@pytest.fixture
def escalation_env():
    """Set up mock SNS, SSM, KMS, and DynamoDB environment."""
    with mock_aws():
        region = "ap-south-1"
        os.environ["AWS_DEFAULT_REGION"] = region
        os.environ["AUDIT_TABLE_NAME"] = "finops-audit-escalation-test"

        sns = boto3.client("sns", region_name=region)
        ssm = boto3.client("ssm", region_name=region)
        kms = boto3.client("kms", region_name=region)
        ddb = boto3.client("dynamodb", region_name=region)

        # Create SNS topic
        topic = sns.create_topic(Name="finops-escalation-topic-test")
        topic_arn = topic["TopicArn"]
        os.environ["SNS_TOPIC_ARN"] = topic_arn
        os.environ["APPROVAL_URL_BASE"] = "https://mock-approval.lambda-url.ap-south-1.on.aws"

        # Create SSM Parameter for HMAC secret
        ssm.put_parameter(
            Name="/finops/hmac-secret",
            Value="test-hmac-secret-key-12345",
            Type="String",
        )

        # Create KMS key
        key = kms.create_key(Description="Escalation Test Key")
        key_id = key["KeyMetadata"]["KeyId"]
        os.environ["KMS_KEY_ARN"] = key_id

        # Create DynamoDB table
        ddb.create_table(
            TableName="finops-audit-escalation-test",
            KeySchema=[{"AttributeName": "log_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "log_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        yield sns, ssm, topic_arn


class TestHmacToken:
    """Test HMAC token signing and verification."""

    def test_valid_token_verifies(self):
        """Valid, unexpired token returns True."""
        secret = "supersecret123"
        expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        token = generate_approval_token("i-12345678", "STOP", expires, secret)

        assert verify_approval_token("i-12345678", "STOP", expires, token, secret) is True

    def test_expired_token_fails(self):
        """Token with past timestamp returns False."""
        secret = "supersecret123"
        expired_ts = int((datetime.now(timezone.utc) - timedelta(seconds=10)).timestamp())
        token = generate_approval_token("i-12345678", "STOP", expired_ts, secret)

        assert verify_approval_token("i-12345678", "STOP", expired_ts, token, secret) is False

    def test_tampered_token_fails(self):
        """Altered signature token returns False."""
        secret = "supersecret123"
        expires = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        token = generate_approval_token("i-12345678", "STOP", expires, secret)
        tampered_token = token[:-2] + "ff"

        assert verify_approval_token("i-12345678", "STOP", expires, tampered_token, secret) is False


class TestEscalationNotification:
    """Test sending escalation emails via SNS."""

    def test_send_escalation_notification(self, escalation_env):
        """Notification generates valid approval URL and publishes to SNS."""
        sns, ssm, topic_arn = escalation_env

        finding = Finding(
            resource_id="i-0987654321fedcba0",
            resource_type="ec2",
            idle_duration_hours=200.0,
            avg_cpu=0.5,
            tags={"Project": "finops-demo", "env": "prod", "owner": "bob@pixelforge.io"},
            estimated_monthly_cost=50.00,
        )

        evaluation = EvaluationResult(
            finding=finding,
            confidence=Confidence.HIGH,
            risk=Risk.HIGH,
            decision=Decision.ESCALATE,
            reason="Prod environment policy override",
        )

        config = Config()
        result = send_escalation_notification(finding, evaluation, config=config, sns_client=sns, ssm_client=ssm)

        assert result["status"] == "ESCALATED"
        assert "message_id" in result
        assert "token=" in result["approval_url"]
        assert "resource_id=i-0987654321fedcba0" in result["approval_url"]

    def test_escalation_handler_with_raw_string_payload(self, escalation_env):
        """Lambda handler correctly converts raw event JSON string values to Enums (C2 regression test)."""
        event = {
            "findings": [
                {
                    "resource_id": "i-0987654321fedcba0",
                    "resource_type": "ec2",
                    "idle_duration_hours": 168.0,
                    "avg_cpu": 0.5,
                    "tags": {"Project": "finops-demo", "env": "prod", "owner": "alice@pixelforge.io"},
                    "estimated_monthly_cost": 30.0,
                    "confidence": "HIGH",
                    "risk": "HIGH",
                    "decision": "ESCALATE",
                    "reason": "Production environment approval required",
                }
            ]
        }

        result = handler(event)
        assert result["status"] == "COMPLETED"
        assert result["count"] == 1
        assert len(result["escalations"]) == 1
        assert result["escalations"][0]["status"] == "ESCALATED"
        assert "token=" in result["escalations"][0]["approval_url"]

    def test_get_hmac_secret_raises_when_missing(self):
        """get_hmac_secret raises RuntimeError when SSM param is missing and no env var exists (M2 security fix)."""
        with mock_aws():
            region = "ap-south-1"
            config = Config()
            ssm = boto3.client("ssm", region_name=region)
            # Remove any HMAC_SECRET in os.environ
            if "HMAC_SECRET" in os.environ:
                del os.environ["HMAC_SECRET"]

            with pytest.raises(RuntimeError) as exc_info:
                get_hmac_secret(config=config, ssm_client=ssm)
            assert "could not be retrieved" in str(exc_info.value)

    def test_escalation_missing_approval_url_base_raises_value_error(self, escalation_env):
        """send_escalation_notification raises ValueError if APPROVAL_URL_BASE is unset (A2.2)."""
        sns, ssm, topic_arn = escalation_env
        finding = Finding(
            resource_id="i-missing-base-url",
            resource_type="ec2",
            idle_duration_hours=200.0,
            avg_cpu=0.5,
            tags={"Project": "finops-demo", "env": "prod"},
            estimated_monthly_cost=50.00,
        )
        evaluation = EvaluationResult(
            finding=finding,
            confidence=Confidence.HIGH,
            risk=Risk.HIGH,
            decision=Decision.ESCALATE,
            reason="Prod escalation",
        )

        old_base = os.environ.get("APPROVAL_URL_BASE")
        try:
            if "APPROVAL_URL_BASE" in os.environ:
                del os.environ["APPROVAL_URL_BASE"]
            config = Config()
            with pytest.raises(ValueError) as exc_info:
                send_escalation_notification(finding, evaluation, config=config, sns_client=sns, ssm_client=ssm)
            assert "APPROVAL_URL_BASE is required" in str(exc_info.value)
        finally:
            if old_base is not None:
                os.environ["APPROVAL_URL_BASE"] = old_base

