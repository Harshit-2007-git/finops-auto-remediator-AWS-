"""
Closed-Loop FinOps Auto-Remediation End-to-End Orchestration Tests.

Covers:
    - T3: Scanner Lambda handler() end-to-end orchestration (auto-remediation + escalation + audit logging)
    - T4: Verification of conftest.py audit_table fixture compatibility with KMS envelope encryption writer
    - Circuit breaker enforcement during automated scans
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
import boto3
import pytest
from moto import mock_aws

from src.audit.writer import read_audit_log, write_audit_log
from src.config import Config
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk
from src.scanner.app import handler as scanner_handler


class TestConftestAuditTableCompatibility:
    """Verify that conftest.py audit_table fixture matches production writer schema."""

    def test_write_and_read_with_conftest_fixture(self, mocked_aws, audit_table, kms_key):
        """Audit table fixture from conftest.py works directly with write_audit_log and read_audit_log."""
        os.environ["AUDIT_TABLE_NAME"] = "finops-audit-log"
        os.environ["KMS_KEY_ARN"] = kms_key
        config = Config()

        finding = Finding(
            resource_id="i-test-conftest-01",
            resource_type="ec2",
            idle_duration_hours=72.0,
            avg_cpu=1.2,
            tags={"Project": "finops-demo", "env": "dev"},
            estimated_monthly_cost=25.0,
        )

        evaluation = EvaluationResult(
            finding=finding,
            confidence=Confidence.HIGH,
            risk=Risk.LOW,
            decision=Decision.AUTO_REMEDIATE,
            reason="Verified dev idle instance",
        )

        write_res = write_audit_log(
            finding=finding,
            evaluation=evaluation,
            action_taken="AUTO_REMEDIATED",
            config=config,
        )

        assert write_res is not None
        log_id = write_res["log_id"]
        assert len(log_id) > 0

        # Read back and verify decrypted content
        record = read_audit_log(log_id=log_id, config=config)
        assert record["log_id"] == log_id
        assert record["resource_id"] == "i-test-conftest-01"
        assert record["action_taken"] == "AUTO_REMEDIATED"
        assert record["details"]["evaluation"]["decision"] == "AUTO_REMEDIATE"


class TestScannerClosedLoopOrchestration:
    """Test full scanner handler execution orchestrating remediation and escalation."""

    @pytest.fixture
    def full_pipeline_env(self):
        """Set up all AWS services required for the closed-loop pipeline."""
        with mock_aws():
            region = "ap-south-1"
            os.environ["AWS_DEFAULT_REGION"] = region
            os.environ["DRY_RUN"] = "false"
            os.environ["DEMO_MODE"] = "true"
            os.environ["DEMO_EC2_IDLE_MINUTES"] = "0"
            os.environ["DEMO_EBS_UNATTACHED_MINUTES"] = "0"
            os.environ["AUDIT_TABLE_NAME"] = "finops-audit-log"
            os.environ["SCOPE_TAG_KEY"] = "Project"
            os.environ["SCOPE_TAG_VALUE"] = "finops-demo"

            ec2 = boto3.client("ec2", region_name=region)
            cw = boto3.client("cloudwatch", region_name=region)
            kms = boto3.client("kms", region_name=region)
            sns = boto3.client("sns", region_name=region)
            ssm = boto3.client("ssm", region_name=region)
            ddb = boto3.client("dynamodb", region_name=region)

            # KMS key
            key = kms.create_key(Description="Pipeline Test Key")
            key_id = key["KeyMetadata"]["KeyId"]
            os.environ["KMS_KEY_ARN"] = key_id
            kms.create_alias(AliasName="alias/finops-key", TargetKeyId=key_id)

            # SNS Topic
            topic = sns.create_topic(Name="finops-escalation-topic")
            os.environ["SNS_TOPIC_ARN"] = topic["TopicArn"]

            # SSM HMAC Secret
            ssm.put_parameter(
                Name="/finops/hmac-secret",
                Value="super-secret-hmac-pipeline-key",
                Type="String",
            )

            # DynamoDB Table
            ddb.create_table(
                TableName="finops-audit-log",
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

            # Seed dev instance (idle -> eligible for AUTO_REMEDIATE)
            dev_resp = ec2.run_instances(
                ImageId="ami-12345678",
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": "dev-api-idle"},
                            {"Key": "Project", "Value": "finops-demo"},
                            {"Key": "env", "Value": "dev"},
                            {"Key": "owner", "Value": "alice@pixelforge.io"},
                        ],
                    }
                ],
            )
            dev_id = dev_resp["Instances"][0]["InstanceId"]

            # Seed prod instance (idle -> should ESCALATE, never auto-stop)
            prod_resp = ec2.run_instances(
                ImageId="ami-12345678",
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": "prod-db-idle"},
                            {"Key": "Project", "Value": "finops-demo"},
                            {"Key": "env", "Value": "prod"},
                            {"Key": "owner", "Value": "bob@pixelforge.io"},
                        ],
                    }
                ],
            )
            prod_id = prod_resp["Instances"][0]["InstanceId"]

            # CloudWatch zero metrics (idle)
            now_metric = datetime.now(timezone.utc) - timedelta(seconds=15)
            cw.put_metric_data(
                Namespace="AWS/EC2",
                MetricData=[
                    {
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "InstanceId", "Value": dev_id}],
                        "Timestamp": now_metric,
                        "Value": 1.0,
                        "Unit": "Percent",
                    },
                    {
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "InstanceId", "Value": prod_id}],
                        "Timestamp": now_metric,
                        "Value": 0.5,
                        "Unit": "Percent",
                    },
                ],
            )

            yield ec2, dev_id, prod_id

    def test_scanner_orchestrates_auto_remediate_and_escalate(self, full_pipeline_env):
        """Scanner automatically remediates dev resources and escalates prod resources."""
        ec2, dev_id, prod_id = full_pipeline_env

        summary = scanner_handler({}, None)

        assert "run_id" in summary
        assert summary["counts"]["total"] >= 2
        assert summary["counts"]["auto_remediate"] >= 1
        assert summary["counts"]["escalate"] >= 1
        assert len(summary["remediations"]) >= 1
        assert len(summary["escalations"]) >= 1

        # Check dev instance was automatically stopped
        dev_desc = ec2.describe_instances(InstanceIds=[dev_id])
        dev_state = dev_desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert dev_state in ["stopping", "stopped"]

        # Check prod instance was NOT stopped (still running)
        prod_desc = ec2.describe_instances(InstanceIds=[prod_id])
        prod_state = prod_desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        assert prod_state == "running"

        # Check escalation contained HMAC approval URL
        esc = summary["escalations"][0]
        assert "token=" in esc["approval_url"]
        assert "resource_id=" in esc["approval_url"]
