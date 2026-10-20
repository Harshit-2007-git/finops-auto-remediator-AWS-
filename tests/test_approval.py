"""
Tests for Approval Handler — Milestone M5 / Milestone 2 Audit Fixes.

Covers:
    - GET /approve: Renders confirmation review form with resource details and impact
    - POST /approve: Atomically consumes token and executes approved remediation (HTTP 200)
    - Replay protection: Submitting the same token a second time returns HTTP 409
    - Safety guards: Approving instance with keep=true returns HTTP 400
    - HTTP 403 error for expired approval URLs
    - HTTP 403 error for tampered signature tokens
    - HTTP 400 error for missing parameters
    - Happy path execution logs zero WARNING or ERROR records (caplog check)
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
import boto3
import pytest
from moto import mock_aws

from src.approval.handler import handler
from src.escalation.handler import generate_approval_token


@pytest.fixture
def approval_env():
    """Set up mock SSM, EC2, KMS, and DynamoDB environment with platform schema."""
    with mock_aws():
        region = "ap-south-1"
        os.environ["AWS_DEFAULT_REGION"] = region
        os.environ["DRY_RUN"] = "false"
        os.environ["AUDIT_TABLE_NAME"] = "finops-audit-approval-test"
        os.environ["SCOPE_TAG_KEY"] = "Project"
        os.environ["SCOPE_TAG_VALUE"] = "finops-demo"
        secret = "test-hmac-secret-key-12345"

        ssm = boto3.client("ssm", region_name=region)
        ec2 = boto3.client("ec2", region_name=region)
        kms = boto3.client("kms", region_name=region)
        ddb = boto3.client("dynamodb", region_name=region)

        # Create SSM Parameter for HMAC secret
        ssm.put_parameter(
            Name="/finops/hmac-secret",
            Value=secret,
            Type="String",
        )

        # Create KMS key
        key = kms.create_key(Description="Approval Test Key")
        key_id = key["KeyMetadata"]["KeyId"]
        os.environ["KMS_KEY_ARN"] = key_id
        kms.create_alias(AliasName="alias/finops-key", TargetKeyId=key_id)

        # Create DynamoDB table with platform multi-tenant composite key
        ddb.create_table(
            TableName="finops-audit-approval-test",
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

        # Create EC2 instance to approve stopping (properly scoped and tagged with env=prod)
        resp = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": "prod-report-01"},
                        {"Key": "Project", "Value": "finops-demo"},
                        {"Key": "env", "Value": "prod"},
                        {"Key": "owner", "Value": "carol@pixelforge.io"},
                    ],
                }
            ],
        )
        instance_id = resp["Instances"][0]["InstanceId"]

        yield secret, instance_id, ec2


class TestApprovalHandler:
    """Test API Gateway two-step approval endpoint."""

    def test_get_approval_renders_confirmation_review_form(self, approval_env):
        """GET request with valid HMAC displays the confirmation form with resource provenance."""
        secret, instance_id, ec2 = approval_env

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expires, secret)

        event = {
            "httpMethod": "GET",
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expires),
                "token": token,
            },
        }

        response = handler(event)

        assert response["statusCode"] == 200
        assert "Content-Type" in response["headers"]
        assert "text/html" in response["headers"]["Content-Type"]
        assert "Confirm Remediation Approval" in response["body"]
        assert instance_id in response["body"]
        assert '<form method="POST" action="/approve"' in response["body"]

    def test_valid_approval_token_executes_remediation(self, approval_env):
        """POST request with valid token triggers remediation and returns HTTP 200 HTML response."""
        secret, instance_id, ec2 = approval_env

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expires, secret)

        event = {
            "httpMethod": "POST",
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expires),
                "token": token,
            },
        }

        response = handler(event)

        assert response["statusCode"] == 200
        assert "Content-Type" in response["headers"]
        assert "text/html" in response["headers"]["Content-Type"]
        assert "Remediation Approved" in response["body"]
        assert instance_id in response["body"]

        # Check instance state changed to stopping/stopped
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert state in ["stopping", "stopped"]

    def test_post_approval_replay_rejected_with_409(self, approval_env):
        """Replaying the same approval token a second time returns HTTP 409 Action Already Executed."""
        secret, instance_id, ec2 = approval_env

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expires, secret)

        event = {
            "httpMethod": "POST",
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expires),
                "token": token,
            },
        }

        # First execution succeeds
        first_resp = handler(event)
        assert first_resp["statusCode"] == 200

        # Second execution with identical token returns HTTP 409
        replay_resp = handler(event)
        assert replay_resp["statusCode"] == 409
        assert "Action Already Executed" in replay_resp["body"]

    def test_approval_rejects_keep_true_guard_with_400(self, approval_env):
        """Safety guard strictly rejects approval if resource has keep=true tag."""
        secret, instance_id, ec2 = approval_env

        # Add keep=true tag
        ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "keep", "Value": "true"}])

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expires, secret)

        event = {
            "httpMethod": "POST",
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expires),
                "token": token,
            },
        }

        response = handler(event)

        assert response["statusCode"] == 400
        assert "Safety Guard Violation" in response["body"]

    def test_approval_happy_path_logs_no_warning_or_error(self, approval_env, caplog):
        """Happy path approval execution produces zero WARNING or ERROR logs."""
        secret, instance_id, ec2 = approval_env

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expires, secret)

        event = {
            "httpMethod": "POST",
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expires),
                "token": token,
            },
        }

        with caplog.at_level(logging.WARNING):
            response = handler(event)

        assert response["statusCode"] == 200
        # Assert caplog contains NO WARNING or ERROR records
        warning_or_error = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warning_or_error) == 0, f"Found unexpected warning/error logs: {warning_or_error}"

    def test_expired_token_returns_403(self, approval_env):
        """Expired timestamp returns HTTP 403 HTML response."""
        secret, instance_id, ec2 = approval_env

        expired_ts = int((datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expired_ts, secret)

        event = {
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expired_ts),
                "token": token,
            }
        }

        response = handler(event)

        assert response["statusCode"] == 403
        assert "Approval Failed" in response["body"]

    def test_tampered_token_returns_403(self, approval_env):
        """Tampered token signature returns HTTP 403 HTML response."""
        secret, instance_id, ec2 = approval_env

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        token = generate_approval_token(instance_id, "STOP", expires, secret)
        tampered_token = token[:-2] + "00"

        event = {
            "queryStringParameters": {
                "resource_id": instance_id,
                "action": "STOP",
                "expires": str(expires),
                "token": tampered_token,
            }
        }

        response = handler(event)

        assert response["statusCode"] == 403
        assert "Approval Failed" in response["body"]

    def test_missing_parameters_returns_400(self, approval_env):
        """Missing parameters return HTTP 400 HTML response."""
        event = {"queryStringParameters": {"resource_id": "i-12345"}}

        response = handler(event)

        assert response["statusCode"] == 400
        assert "Missing Parameters" in response["body"]
