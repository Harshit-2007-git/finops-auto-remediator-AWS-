"""Regression test: the scanner Lambda must publish CloudWatch metrics using the real Config object.

In the first real-AWS run the scanner logged "Failed publishing CloudWatch metrics: 'Config' object has no
attribute 'aws_region'" because app.py read a field that does not exist. The error was swallowed, so the
dashboard stayed empty. This test uses the real Config and fails on any such logged error.
"""
from __future__ import annotations

import logging
import os

import boto3
from moto import mock_aws

from src.scanner.app import handler as scanner_handler


def test_scanner_publishes_finops_metrics_without_errors(caplog):
    with mock_aws():
        os.environ["AWS_DEFAULT_REGION"] = "ap-south-1"
        os.environ["DRY_RUN"] = "true"
        with caplog.at_level(logging.WARNING):
            scanner_handler({}, None)
        errors = [r.getMessage() for r in caplog.records if "metrics" in r.getMessage().lower()]
        assert not errors, f"metrics publishing logged problems: {errors}"
        cw = boto3.client("cloudwatch", region_name="ap-south-1")
        names = {m["MetricName"] for m in cw.list_metrics(Namespace="FinOps")["Metrics"]}
        assert "ResourcesScanned" in names
