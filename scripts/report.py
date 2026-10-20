#!/usr/bin/env python3
"""
Report script — generates a FinOps audit summary report from DynamoDB.

Decrypts all KMS envelope-encrypted records in the audit log and prints
a formatted summary report of waste detected, actions taken, and cost savings.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import boto3

from src.audit.writer import read_audit_log
from src.config import Config, get_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def generate_report(config: Config | None = None, ddb_client: Any = None, kms_client: Any = None):
    """Generate and print FinOps audit report."""
    if config is None:
        config = get_config()
    if ddb_client is None:
        ddb_client = boto3.client("dynamodb", region_name=config.region)

    table_name = config.audit_table_name
    logger.info("Reading audit entries from DynamoDB table %s...", table_name)

    try:
        response = ddb_client.scan(TableName=table_name)
    except Exception as e:
        logger.error("Could not scan audit table %s: %s", table_name, e)
        print(f"\n[ERROR] Table '{table_name}' not found or inaccessible.")
        return

    items = response.get("Items", [])
    logger.info("Found %d records in audit table", len(items))

    total_scanned = len(items)
    actions_count: dict[str, int] = {}
    resource_type_count: dict[str, int] = {}
    total_monthly_savings = 0.0

    decrypted_records = []

    for item in items:
        log_id = item["log_id"]["S"]
        if log_id.startswith("APPROVAL_TOKEN#"):
            continue
        item_tenant = item.get("tenant_id", {}).get("S")
        try:
            rec = read_audit_log(
                log_id=log_id,
                config=config,
                dynamodb_client=ddb_client,
                kms_client=kms_client,
                tenant_id=item_tenant,
            )
            decrypted_records.append(rec)

            action = rec["action_taken"]
            r_type = rec["resource_type"].upper()
            savings = rec["estimated_savings"]

            actions_count[action] = actions_count.get(action, 0) + 1
            resource_type_count[r_type] = resource_type_count.get(r_type, 0) + 1
            total_monthly_savings += savings

        except Exception as e:
            logger.warning("Could not decrypt log_id %s: %s", log_id, e)

    # Print formatted report
    print("\n" + "=" * 70)
    print(f"       FINOPS AUTO-REMEDIATION AUDIT REPORT — {config.company.upper()} STUDIOS       ")
    print("=" * 70)
    print(f"Region:                      {config.region}")
    print(f"Audit Table:                 {table_name}")
    print(f"KMS Key Alias:               {config.kms_key_alias}")
    print(f"Dry Run Mode:                {config.dry_run}")
    print("-" * 70)
    print(f"Total Waste Findings:        {total_scanned}")
    print(f"Total Estimated Savings:     ${total_monthly_savings:.2f} / month (${total_monthly_savings * 12:.2f} / year)")
    print("-" * 70)
    print("ACTIONS BREAKDOWN:")
    for action, cnt in sorted(actions_count.items()):
        print(f"  - {action:<26}: {cnt}")
    print("-" * 70)
    print("RESOURCE TYPES BREAKDOWN:")
    for r_type, cnt in sorted(resource_type_count.items()):
        print(f"  - {r_type:<26}: {cnt}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    generate_report()
