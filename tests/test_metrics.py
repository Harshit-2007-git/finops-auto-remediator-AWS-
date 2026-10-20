"""
Tests for CloudWatch Custom Metrics Publisher (src/metrics.py) — Milestone M5 (N8).

Covers:
    - Namespace is strictly 'FinOps'
    - Total metric definitions stay <= 8 (within AWS Free Tier of 10)
    - Zero dimensions enforced (NO tenant dimension to prevent multi-series billing charges)
    - Metric publishing roundtrip under moto mock
    - Graceful error handling on CloudWatch failures
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from src.metrics import (
    METRIC_DEFINITIONS,
    NAMESPACE,
    publish_finops_metrics,
)


class TestFinOpsMetrics:
    """Test suite for CloudWatch custom metrics publisher."""

    def test_namespace_is_finops(self):
        """Namespace must be 'FinOps'."""
        assert NAMESPACE == "FinOps"

    def test_metric_count_within_free_tier_limit(self):
        """Total defined metrics must stay <= 8 (AWS Free Tier provides up to 10 custom metrics)."""
        assert len(METRIC_DEFINITIONS) <= 8
        assert len(METRIC_DEFINITIONS) == 8

    def test_zero_dimensions_enforced(self):
        """Published metrics must NOT contain a tenant or company dimension to avoid multi-series charges."""
        captured_data = []

        class DummyCW:
            def put_metric_data(self, Namespace, MetricData):
                assert Namespace == "FinOps"
                captured_data.extend(MetricData)

        test_metrics = {
            "ResourcesScanned": 8,
            "IdleEC2Detected": 4,
            "UnattachedEBSDetected": 2,
            "AutoRemediatedActions": 3,
            "EscalatedActions": 2,
            "EstimatedMonthlySavings": 38.19,
            "RealizedMonthlySavings": 15.26,
            "RemediationFailures": 0,
        }

        success = publish_finops_metrics(test_metrics, cw_client=DummyCW())
        assert success is True
        assert len(captured_data) == 8

        for item in captured_data:
            assert item["Dimensions"] == [], f"Metric {item['MetricName']} has non-empty dimensions: {item['Dimensions']}"
            assert item["MetricName"] in test_metrics
            assert item["Value"] == float(test_metrics[item["MetricName"]])

    @mock_aws
    def test_publish_to_mocked_cloudwatch(self):
        """Publishing to mocked CloudWatch succeeds and stores metrics."""
        cw = boto3.client("cloudwatch", region_name="ap-south-1")

        test_metrics = {
            "ResourcesScanned": 8,
            "IdleEC2Detected": 3,
            "AutoRemediatedActions": 3,
            "EstimatedMonthlySavings": 22.85,
        }

        success = publish_finops_metrics(test_metrics, cw_client=cw)
        assert success is True

        # Verify CloudWatch has metric data
        paginator = cw.get_paginator("list_metrics")
        found_metrics = set()
        for page in paginator.paginate(Namespace="FinOps"):
            for m in page["Metrics"]:
                found_metrics.add(m["MetricName"])

        assert "ResourcesScanned" in found_metrics
        assert "IdleEC2Detected" in found_metrics
        assert "AutoRemediatedActions" in found_metrics
        assert "EstimatedMonthlySavings" in found_metrics

    def test_empty_metrics_returns_true(self):
        """Passing an empty dict or unrecognized metrics handles gracefully without API call."""
        success = publish_finops_metrics({})
        assert success is True

    def test_cw_error_handled_gracefully(self):
        """Client exceptions are logged and return False rather than crashing."""
        class FailingCW:
            def put_metric_data(self, **kwargs):
                raise RuntimeError("CloudWatch service unavailable")

        success = publish_finops_metrics({"ResourcesScanned": 5}, cw_client=FailingCW())
        assert success is False
