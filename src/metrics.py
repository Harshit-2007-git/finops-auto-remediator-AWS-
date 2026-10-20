"""
CloudWatch Custom Metrics Publisher for FinOps Auto-Remediation.

Complies strictly with AWS Free Tier constraints:
- Namespace: FinOps
- Zero dimensions (NO tenant dimension): Every dimension combination counts as a distinct custom metric.
  AWS Free Tier includes 10 custom metrics, so we publish exactly 8 zero-dimension metrics.
"""

from __future__ import annotations

import logging
from typing import Any

import boto3

logger = logging.getLogger(__name__)

NAMESPACE = "FinOps"

# Canonical 8 metrics (staying <= 8 to fit within 10 free-tier custom metrics)
METRIC_DEFINITIONS = [
    ("ResourcesScanned", "Count"),
    ("IdleEC2Detected", "Count"),
    ("UnattachedEBSDetected", "Count"),
    ("AutoRemediatedActions", "Count"),
    ("EscalatedActions", "Count"),
    ("EstimatedMonthlySavings", "None"),  # Currency / scalar
    ("RealizedMonthlySavings", "None"),
    ("RemediationFailures", "Count"),
]


def publish_finops_metrics(
    metrics: dict[str, float | int],
    cw_client: Any = None,
    region: str = "ap-south-1",
) -> bool:
    """Publish FinOps metrics to CloudWatch.

    Args:
        metrics: Dictionary mapping metric name to value.
        cw_client: Optional boto3 CloudWatch client.
        region: AWS region if cw_client needs to be instantiated.

    Returns:
        bool: True if metrics were published successfully, False otherwise.
    """
    if cw_client is None:
        cw_client = boto3.client("cloudwatch", region_name=region)

    metric_data = []
    for name, unit in METRIC_DEFINITIONS:
        if name in metrics:
            val = float(metrics[name])
            metric_data.append({
                "MetricName": name,
                "Value": val,
                "Unit": unit,
                # Explicitly empty dimensions to avoid multi-series billing charges
                "Dimensions": [],
            })

    if not metric_data:
        logger.debug("No matching FinOps metrics to publish.")
        return True

    try:
        # PutMetricData accepts up to 20 metric data points per call
        cw_client.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=metric_data,
        )
        logger.info("Published %d FinOps metrics to CloudWatch namespace '%s'", len(metric_data), NAMESPACE)
        return True
    except Exception as e:
        logger.error("Failed to publish CloudWatch metrics: %s", e)
        return False
