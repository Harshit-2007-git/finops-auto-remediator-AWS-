"""Regression test for the real-AWS bug where clicking Approve showed
"The approval URL is incomplete or corrupted".

Lambda Function URLs (payload v2.0) deliver the confirm form's POST body base64-encoded
(isBase64Encoded=true). The handler did not decode it, so it saw no parameters.
"""
from __future__ import annotations

import base64
import time
from urllib.parse import urlencode

import boto3
import pytest
from moto import mock_aws

from src.approval.handler import handler as approval_handler
from src.escalation.handler import generate_approval_token


@pytest.fixture()
def approval_env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    monkeypatch.setenv("DRY_RUN", "false")
    monkeypatch.setenv("HMAC_SECRET", "test-secret")
    monkeypatch.setenv("SCOPE_TAG_KEY", "Project")
    monkeypatch.setenv("SCOPE_TAG_VALUE", "finops-demo")
    monkeypatch.setenv("AUDIT_TABLE_NAME", "finops-audit-log")
    with mock_aws():
        ec2 = boto3.client("ec2")
        ddb = boto3.client("dynamodb")
        monkeypatch.setenv("KMS_KEY_ARN", boto3.client("kms").create_key()["KeyMetadata"]["KeyId"])
        ddb.create_table(
            TableName="finops-audit-log",
            KeySchema=[{"AttributeName": "tenant_id", "KeyType": "HASH"}, {"AttributeName": "log_id", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "tenant_id", "AttributeType": "S"}, {"AttributeName": "log_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        inst = ec2.run_instances(
            ImageId="ami-12345678", InstanceType="t3.micro", MinCount=1, MaxCount=1,
            TagSpecifications=[{"ResourceType": "instance", "Tags": [
                {"Key": "Name", "Value": "prod-report-01"}, {"Key": "Project", "Value": "finops-demo"},
                {"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "a@b.c"}]}],
        )["Instances"][0]["InstanceId"]
        yield ec2, inst


def _params(rid):
    exp = int(time.time()) + 3600
    return {"resource_id": rid, "action": "STOP", "expires": str(exp),
            "token": generate_approval_token(rid, "STOP", exp, "test-secret")}


def _state(ec2, rid):
    return ec2.describe_instances(InstanceIds=[rid])["Reservations"][0]["Instances"][0]["State"]["Name"]


def test_function_url_get_then_base64_form_post_executes(approval_env):
    ec2, rid = approval_env
    q = _params(rid)
    get_event = {"version": "2.0", "rawQueryString": urlencode(q), "queryStringParameters": q,
                 "requestContext": {"http": {"method": "GET"}}, "isBase64Encoded": False}
    resp = approval_handler(get_event)
    assert resp["statusCode"] == 200 and "<form" in resp["body"]
    assert _state(ec2, rid) == "running"

    post_event = {"version": "2.0", "rawQueryString": "", "requestContext": {"http": {"method": "POST"}},
                  "headers": {"content-type": "application/x-www-form-urlencoded"},
                  "body": base64.b64encode(urlencode(q).encode()).decode(), "isBase64Encoded": True}
    resp = approval_handler(post_event)
    assert resp["statusCode"] == 200, resp["body"]
    assert "incomplete or corrupted" not in resp["body"]
    assert _state(ec2, rid) == "stopped"

    # single-use: replaying the same approval is refused
    assert approval_handler(post_event)["statusCode"] == 409


def test_raw_query_string_is_enough_when_parsed_dict_is_missing(approval_env):
    ec2, rid = approval_env
    q = _params(rid)
    event = {"version": "2.0", "rawQueryString": urlencode(q), "requestContext": {"http": {"method": "GET"}}}
    resp = approval_handler(event)
    assert resp["statusCode"] == 200 and "<form" in resp["body"]


def test_failed_remediation_does_not_burn_the_approval_link(approval_env, monkeypatch):
    """If the stop/delete itself fails (e.g. missing IAM permission), the single-use link must stay usable."""
    import importlib

    ah = importlib.import_module("src.approval.handler")

    ec2, rid = approval_env
    q = _params(rid)
    post_event = {"version": "2.0", "rawQueryString": "", "requestContext": {"http": {"method": "POST"}},
                  "body": base64.b64encode(urlencode(q).encode()).decode(), "isBase64Encoded": True}

    real = ah.remediate_resource

    def boom(*a, **k):
        raise RuntimeError("UnauthorizedOperation: simulated missing permission")

    monkeypatch.setattr(ah, "remediate_resource", boom)
    resp = approval_handler(post_event)
    assert resp["statusCode"] == 500
    assert _state(ec2, rid) == "running"

    monkeypatch.setattr(ah, "remediate_resource", real)  # permission fixed
    resp = approval_handler(post_event)
    assert resp["statusCode"] == 200, resp["body"]
    assert _state(ec2, rid) == "stopped"
