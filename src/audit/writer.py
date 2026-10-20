"""
Audit Writer module — records every evaluation and action into DynamoDB.

Every decision (AUTO_REMEDIATED, ESCALATED, LOG_ONLY, SKIPPED) is stored as an
item in the DynamoDB Audit Table. Sensitive details are encrypted using
KMS Envelope Encryption before storage.

Audit Table Schema (Platform Storage):
    - Partition Key: tenant_id (String)
    - Sort Key: log_id (String)
    - Plaintext attributes: run_id, finding_id, resource_id, resource_type,
      timestamp, decision, action_taken, status, company, environment,
      estimated_savings, dry_run, ttl
    - KMS Envelope Encryption Context: {"tenant_id": tenant_id, "run_id": run_id}
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

from src.config import Config, get_config
from src.crypto.envelope import decrypt_payload, encrypt_payload
from src.policy_engine import EvaluationResult, Finding

logger = logging.getLogger(__name__)


def write_audit_log(
    finding: Finding,
    evaluation: EvaluationResult,
    action_taken: str,
    config: Config | None = None,
    dynamodb_client: Any = None,
    kms_client: Any = None,
    tenant_id: str | None = None,
    run_id: str | None = None,
    kms_key_id: str | None = None,
) -> dict[str, Any]:
    """Write an encrypted audit log entry to DynamoDB.

    Args:
        finding: The resource finding.
        evaluation: Policy engine evaluation result.
        action_taken: Action executed (AUTO_REMEDIATED, ESCALATED, LOG_ONLY, SKIPPED).
        config: Config instance (defaults to get_config()).
        dynamodb_client: boto3 DynamoDB client (created if None).
        kms_client: boto3 KMS client (created if None).
        tenant_id: Tenant identifier (defaults to config.tenant_id or config.company).
        run_id: Execution scan/run ID (defaults to new UUID).
        kms_key_id: Optional KMS key ARN/ID for tenant BYOK or platform CMK.

    Returns:
        Dict representing the stored audit record (including log_id, tenant_id, run_id).
    """
    if config is None:
        config = get_config()
    if dynamodb_client is None:
        dynamodb_client = boto3.client("dynamodb", region_name=config.region)

    if tenant_id is None:
        tenant_id = getattr(config, "tenant_id", None) or getattr(config, "company", "pixelforge")
    if run_id is None:
        run_id = str(uuid.uuid4())

    log_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    timestamp_str = now.isoformat()
    ttl_epoch = int((now + timedelta(days=90)).timestamp())

    # Build unencrypted audit details dict
    details = {
        "finding": finding.to_dict(),
        "evaluation": evaluation.to_dict(),
        "action_taken": action_taken,
        "company": config.company,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "environment": finding.tags.get("env", "unknown"),
        "remediated_by": "FinOpsAutoRemediation",
        "dry_run": config.dry_run,
    }

    # Encryption context for KMS envelope encryption
    encryption_context = {
        "tenant_id": tenant_id,
        "run_id": run_id,
    }

    # Encrypt details with KMS envelope encryption
    if kms_key_id is None:
        kms_key_id = getattr(config, "kms_key_arn", None) or getattr(config, "kms_key_alias", "alias/finops-key")
    envelope = encrypt_payload(
        data=details,
        kms_key_id=kms_key_id,
        kms_client=kms_client,
        encryption_context=encryption_context,
    )

    decision_str = (
        evaluation.decision.value
        if hasattr(evaluation.decision, "value")
        else str(evaluation.decision)
    )

    # Prepare DynamoDB item (Partition Key: tenant_id, Sort Key: log_id)
    item = {
        "tenant_id": {"S": tenant_id},
        "log_id": {"S": log_id},
        "run_id": {"S": run_id},
        "finding_id": {"S": finding.resource_id},
        "resource_id": {"S": finding.resource_id},
        "resource_type": {"S": finding.resource_type},
        "timestamp": {"S": timestamp_str},
        "decision": {"S": decision_str},
        "action_taken": {"S": action_taken},
        "status": {"S": "COMPLETED"},
        "company": {"S": config.company},
        "environment": {"S": finding.tags.get("env", "unknown")},
        "estimated_savings": {"N": str(finding.estimated_monthly_cost)},
        "dry_run": {"BOOL": config.dry_run},
        "ttl": {"N": str(ttl_epoch)},
        # Encrypted envelope components stored as JSON/b64 string
        "ciphertext_b64": {"S": envelope["ciphertext_b64"]},
        "encrypted_data_key_b64": {"S": envelope["encrypted_data_key_b64"]},
        "nonce_b64": {"S": envelope["nonce_b64"]},
        "kms_key_id": {"S": envelope["kms_key_id"]},
    }

    table_name = config.audit_table_name
    logger.info(
        "Writing audit log %s (tenant=%s, run=%s) for %s (%s) to DynamoDB table %s",
        log_id,
        tenant_id,
        run_id,
        finding.resource_id,
        action_taken,
        table_name,
    )

    dynamodb_client.put_item(
        TableName=table_name,
        Item=item,
    )

    return {
        "log_id": log_id,
        "tenant_id": tenant_id,
        "run_id": run_id,
        "timestamp": timestamp_str,
        "resource_id": finding.resource_id,
        "action_taken": action_taken,
        "envelope": envelope,
    }


def read_audit_log(
    log_id: str,
    config: Config | None = None,
    dynamodb_client: Any = None,
    kms_client: Any = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Retrieve and decrypt an audit log record from DynamoDB.

    Args:
        log_id: UUID of the audit log entry.
        config: Config instance (defaults to get_config()).
        dynamodb_client: boto3 DynamoDB client (created if None).
        kms_client: boto3 KMS client (created if None).
        tenant_id: Tenant identifier (defaults to config.tenant_id or config.company).

    Returns:
        Dict containing top-level metadata and decrypted details payload.

    Raises:
        ValueError: If record not found or decryption fails.
    """
    if config is None:
        config = get_config()
    if dynamodb_client is None:
        dynamodb_client = boto3.client("dynamodb", region_name=config.region)

    if tenant_id is None:
        tenant_id = getattr(config, "tenant_id", None) or getattr(config, "company", "pixelforge")

    table_name = config.audit_table_name

    # Try composite key (tenant_id, log_id) first, fallback to single key log_id
    item = None
    try:
        response = dynamodb_client.get_item(
            TableName=table_name,
            Key={"tenant_id": {"S": tenant_id}, "log_id": {"S": log_id}},
        )
        item = response.get("Item")
    except Exception:
        pass

    if not item:
        try:
            response = dynamodb_client.get_item(
                TableName=table_name,
                Key={"log_id": {"S": log_id}},
            )
            item = response.get("Item")
        except Exception:
            pass

    if not item:
        raise ValueError(f"Audit record not found: {log_id}")

    # Reconstruct envelope dict
    resource_id = item.get("resource_id", {}).get("S", "")
    company = item.get("company", {}).get("S", config.company)
    record_tenant = item.get("tenant_id", {}).get("S", tenant_id)
    run_id = item.get("run_id", {}).get("S", "")

    envelope = {
        "ciphertext_b64": item["ciphertext_b64"]["S"],
        "encrypted_data_key_b64": item["encrypted_data_key_b64"]["S"],
        "nonce_b64": item["nonce_b64"]["S"],
        "kms_key_id": item["kms_key_id"]["S"],
        "encryption_context": {
            "tenant_id": record_tenant,
            "run_id": run_id,
        },
    }

    # Decrypt with tenant/run context, fallback to legacy context if needed
    try:
        details = decrypt_payload(envelope=envelope, kms_client=kms_client)
    except Exception:
        envelope["encryption_context"] = {
            "company": company,
            "resource_id": resource_id,
            "log_id": log_id,
        }
        details = decrypt_payload(envelope=envelope, kms_client=kms_client)

    return {
        "log_id": log_id,
        "tenant_id": record_tenant,
        "run_id": run_id,
        "timestamp": item["timestamp"]["S"],
        "resource_id": resource_id,
        "resource_type": item.get("resource_type", {}).get("S", "unknown"),
        "action_taken": item.get("action_taken", {}).get("S", "UNKNOWN"),
        "company": company,
        "estimated_savings": float(item.get("estimated_savings", {}).get("N", "0.0")),
        "dry_run": item.get("dry_run", {}).get("BOOL", True),
        "details": details,
    }
