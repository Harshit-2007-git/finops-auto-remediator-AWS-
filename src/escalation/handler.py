"""
Escalation Handler module — sends human-in-the-loop approval emails via SNS.

Generates time-limited, HMAC-SHA256 signed approval URLs for risky resources.
When clicked, the link allows authorized managers to confirm resource remediation.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import boto3

from src.audit.writer import write_audit_log
from src.config import Config, get_config
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk

logger = logging.getLogger(__name__)


def generate_approval_token(
    resource_id: str,
    action: str,
    expires_at_epoch: int,
    secret_key: str,
) -> str:
    """Generate a cryptographic HMAC-SHA256 signature token for an approval link.

    Args:
        resource_id: AWS resource ID (e.g. 'i-12345678')
        action: Intended action (e.g. 'STOP', 'DELETE')
        expires_at_epoch: Expiration timestamp in epoch seconds
        secret_key: HMAC secret key string

    Returns:
        Hex-encoded HMAC-SHA256 signature digest string.
    """
    message = f"{resource_id}:{action}:{expires_at_epoch}"
    signature = hmac.new(
        secret_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return signature


def verify_approval_token(
    resource_id: str,
    action: str,
    expires_at_epoch: int,
    token: str,
    secret_key: str,
) -> bool:
    """Verify an HMAC approval token using constant-time comparison.

    Args:
        resource_id: AWS resource ID
        action: Intended action
        expires_at_epoch: Expiration timestamp in epoch seconds
        token: Hex token string to verify
        secret_key: HMAC secret key string

    Returns:
        True if valid and unexpired; False otherwise.
    """
    # Check expiration
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    if now_epoch > expires_at_epoch:
        logger.warning("Approval token expired for %s (expires=%d, now=%d)", resource_id, expires_at_epoch, now_epoch)
        return False

    expected_token = generate_approval_token(resource_id, action, expires_at_epoch, secret_key)
    return hmac.compare_digest(token, expected_token)


def get_hmac_secret(config: Config, ssm_client: Any = None) -> str:
    """Fetch the HMAC secret key from SSM Parameter Store or HMAC_SECRET env var.
    
    Raises:
        RuntimeError: If HMAC secret cannot be retrieved, preventing insecure token signing.
    """
    # Check environment variable first (useful for dev/test environments)
    env_secret = os.environ.get("HMAC_SECRET")
    if env_secret:
        return env_secret

    param_name = config.hmac_param_name
    if ssm_client is None:
        ssm_client = boto3.client("ssm", region_name=config.region)

    try:
        resp = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except Exception as e:
        logger.error("Could not fetch SSM parameter %s (%s). No fallback key allowed.", param_name, e)
        raise RuntimeError(
            f"HMAC secret parameter '{param_name}' could not be retrieved from SSM Parameter Store. "
            "Refusing to proceed with insecure fallback."
        ) from e


def send_escalation_notification(
    finding: Finding,
    evaluation: EvaluationResult,
    config: Config | None = None,
    sns_client: Any = None,
    ssm_client: Any = None,
) -> dict[str, Any]:
    """Build and publish an escalation email to the SNS topic.

    Args:
        finding: The risky resource finding.
        evaluation: Policy evaluation result.
        config: Application config.
        sns_client: boto3 SNS client.
        ssm_client: boto3 SSM client.

    Returns:
        Dict with status, message_id, and approval_url.
    """
    if config is None:
        config = get_config()
    if sns_client is None:
        sns_client = boto3.client("sns", region_name=config.region)

    secret_key = get_hmac_secret(config, ssm_client)

    # Token valid for 48 hours
    expires_at_epoch = int((datetime.now(timezone.utc) + timedelta(hours=48)).timestamp())
    action_type = "STOP" if finding.resource_type == "ec2" else "DELETE"

    base_url = config.approval_url_base
    if not base_url:
        logger.error("APPROVAL_URL_BASE is missing or not configured. Cannot generate approval link.")
        raise ValueError("APPROVAL_URL_BASE is required and must be configured.")

    token = generate_approval_token(finding.resource_id, action_type, expires_at_epoch, secret_key)
    query_params = {
        "resource_id": finding.resource_id,
        "action": action_type,
        "expires": str(expires_at_epoch),
        "token": token,
    }
    approval_url = f"{base_url}?{urlencode(query_params)}"

    owner = finding.tags.get("owner", "unassigned@pixelforge.io")
    env = finding.tags.get("env", "unknown")

    subject = f"[FinOps Escalation] Action Required: Waste detected on {finding.resource_id} ({env})"
    body = f"""
===================================================================
FinOps Auto-Remediation Escalation Request — PixelForge Studios
===================================================================

A wasted AWS resource requires human approval before remediation:

Resource ID:       {finding.resource_id}
Resource Type:     {finding.resource_type.upper()}
Environment:       {env}
Owner:             {owner}
Idle Duration:     {finding.idle_duration_hours:.1f} hours
Avg CPU:           {f"{finding.avg_cpu:.1f}%" if finding.avg_cpu is not None else "N/A"}
Estimated Cost:    ${finding.estimated_monthly_cost:.2f}/month

EVALUATION DETAILS:
Confidence:        {evaluation.confidence.value}
Risk Level:        {evaluation.risk.value}
Reason:            {evaluation.reason}

APPROVAL INSTRUCTIONS:
This resource requires manual confirmation to stop/delete because it is in a sensitive environment or tagged high-risk.

To approve remediation and release these cloud costs, click the link below (valid for 48 hours):

>>> APPROVE REMEDIATION:
{approval_url}

If no action is taken within 48 hours, this request will expire and be re-flagged on the next audit scan.

===================================================================
FinOps Auto-Remediation System | Powered by AWS Lambda & KMS
"""

    topic_arn = config.sns_topic_arn or "arn:aws:sns:ap-south-1:123456789012:finops-escalation-topic"
    logger.info("Publishing escalation message for %s to SNS topic %s", finding.resource_id, topic_arn)

    pub_resp = sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=body,
    )

    message_id = pub_resp.get("MessageId", "mock-msg-id")

    # Record escalation in audit log
    write_audit_log(
        finding=finding,
        evaluation=evaluation,
        action_taken="ESCALATED",
        config=config,
    )

    return {
        "status": "ESCALATED",
        "resource_id": finding.resource_id,
        "message_id": message_id,
        "approval_url": approval_url,
    }


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Lambda handler for sending escalations."""
    config = get_config()
    findings_raw = event.get("findings", [])
    results = []

    for f_dict in findings_raw:
        finding = Finding(
            resource_id=f_dict["resource_id"],
            resource_type=f_dict["resource_type"],
            idle_duration_hours=f_dict.get("idle_duration_hours", 0.0),
            avg_cpu=f_dict.get("avg_cpu"),
            tags=f_dict.get("tags", {}),
            estimated_monthly_cost=f_dict.get("estimated_monthly_cost", 0.0),
        )

        conf_val = f_dict.get("confidence", "HIGH")
        risk_val = f_dict.get("risk", "HIGH")
        dec_val = f_dict.get("decision", "ESCALATE")

        confidence = conf_val if isinstance(conf_val, Confidence) else Confidence(str(conf_val))
        risk = risk_val if isinstance(risk_val, Risk) else Risk(str(risk_val))
        decision = dec_val if isinstance(dec_val, Decision) else Decision(str(dec_val))

        evaluation = EvaluationResult(
            finding=finding,
            confidence=confidence,
            risk=risk,
            decision=decision,
            reason=f_dict.get("reason", "Escalation requested"),
        )

        res = send_escalation_notification(finding, evaluation, config=config)
        results.append(res)

    return {
        "status": "COMPLETED",
        "count": len(results),
        "escalations": results,
    }
