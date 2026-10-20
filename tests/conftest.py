"""
Shared pytest fixtures for FinOps Auto-Remediation tests.

Provides:
    - Mocked AWS credentials (prevents any real AWS calls)
    - Moto mock_aws fixture for all tests
    - Common resource creation helpers
"""

from __future__ import annotations

import os
import pytest
import boto3
from moto import mock_aws


# ---------------------------------------------------------------------------
# Fake AWS credentials — ensures no real AWS calls can leak
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def aws_credentials():
    """Set dummy AWS credentials for moto. Applied to ALL tests."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"
    os.environ["FINOPS_OFFLINE_TEST"] = "1"
    yield
    # Cleanup is not strictly necessary since each test gets fresh env,
    # but it's good practice.


@pytest.fixture
def mocked_aws(aws_credentials):
    """Activate moto mock for all AWS services."""
    with mock_aws():
        yield


# ---------------------------------------------------------------------------
# Boto3 client / resource fixtures (require mocked_aws)
# ---------------------------------------------------------------------------
@pytest.fixture
def ec2_client(mocked_aws):
    """Return a mocked EC2 client."""
    return boto3.client("ec2", region_name="ap-south-1")


@pytest.fixture
def ec2_resource(mocked_aws):
    """Return a mocked EC2 resource."""
    return boto3.resource("ec2", region_name="ap-south-1")


@pytest.fixture
def cloudwatch_client(mocked_aws):
    """Return a mocked CloudWatch client."""
    return boto3.client("cloudwatch", region_name="ap-south-1")


@pytest.fixture
def dynamodb_client(mocked_aws):
    """Return a mocked DynamoDB client."""
    return boto3.client("dynamodb", region_name="ap-south-1")


@pytest.fixture
def dynamodb_resource(mocked_aws):
    """Return a mocked DynamoDB resource."""
    return boto3.resource("dynamodb", region_name="ap-south-1")


@pytest.fixture
def kms_client(mocked_aws):
    """Return a mocked KMS client."""
    return boto3.client("kms", region_name="ap-south-1")


@pytest.fixture
def sns_client(mocked_aws):
    """Return a mocked SNS client."""
    return boto3.client("sns", region_name="ap-south-1")


@pytest.fixture
def ssm_client(mocked_aws):
    """Return a mocked SSM client."""
    return boto3.client("ssm", region_name="ap-south-1")


# ---------------------------------------------------------------------------
# KMS key fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def kms_key(kms_client):
    """Create a mocked KMS key and return the key ID."""
    response = kms_client.create_key(
        Description="FinOps test key",
        KeyUsage="ENCRYPT_DECRYPT",
    )
    key_id = response["KeyMetadata"]["KeyId"]
    kms_client.create_alias(
        AliasName="alias/finops-key",
        TargetKeyId=key_id,
    )
    return key_id


# ---------------------------------------------------------------------------
# DynamoDB audit table fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def audit_table(dynamodb_resource):
    """Create the finops-audit-log DynamoDB table matching production schema."""
    table = dynamodb_resource.create_table(
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
    table.wait_until_exists()
    return table


# ---------------------------------------------------------------------------
# Helper: create a tagged EC2 instance
# ---------------------------------------------------------------------------
@pytest.fixture
def create_ec2_instance(ec2_client):
    """Factory fixture to create a tagged EC2 instance."""

    def _create(
        name: str = "test-instance",
        env: str = "dev",
        project: str = "finops-demo",
        keep: str | None = None,
        owner: str = "test-owner",
        instance_type: str = "t3.micro",
    ) -> str:
        tags = [
            {"Key": "Name", "Value": name},
            {"Key": "Project", "Value": project},
            {"Key": "env", "Value": env},
            {"Key": "owner", "Value": owner},
        ]
        if keep is not None:
            tags.append({"Key": "keep", "Value": keep})

        response = ec2_client.run_instances(
            ImageId="ami-12345678",
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": tags,
                }
            ],
        )
        return response["Instances"][0]["InstanceId"]

    return _create


# ---------------------------------------------------------------------------
# Helper: create a tagged EBS volume
# ---------------------------------------------------------------------------
@pytest.fixture
def create_ebs_volume(ec2_client):
    """Factory fixture to create a tagged EBS volume."""

    def _create(
        name: str = "test-volume",
        env: str = "dev",
        project: str = "finops-demo",
        size_gb: int = 1,
        volume_type: str = "gp3",
        owner: str = "test-owner",
    ) -> str:
        response = ec2_client.create_volume(
            AvailabilityZone="ap-south-1a",
            Size=size_gb,
            VolumeType=volume_type,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "Name", "Value": name},
                        {"Key": "Project", "Value": project},
                        {"Key": "env", "Value": env},
                        {"Key": "owner", "Value": owner},
                    ],
                }
            ],
        )
        return response["VolumeId"]

    return _create
