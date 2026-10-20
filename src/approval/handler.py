"""
Approval Handler module — API Gateway endpoint for processing manager approval links.

Validates time-limited HMAC signatures. When valid, implements a replay-safe
two-step human approval workflow:
    1. GET /approve: Renders confirmation review form with resource provenance and impact.
    2. POST /approve: Atomically consumes the single-use token via DynamoDB conditional write
       (attribute_not_exists), executes remediation under mode='approved', and records audit log.

Guards:
    - Imports boto3 (N1 fix) and fails closed if describe_instances / describe_volumes fails.
    - Strictly enforces assert_actionable(finding, mode='approved'): allows env=prod,
      but strictly forbids keep=true and untagged resources (N3 fix).
    - Prevents replay attacks via atomic DynamoDB token consumption (N4 fix).
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

import boto3

from src.audit.writer import write_audit_log
from src.config import Config, get_config
from src.escalation.handler import get_hmac_secret, verify_approval_token
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk
from src.remediation.handler import assert_actionable, remediate_resource

logger = logging.getLogger(__name__)


def build_html_response(
    status_code: int,
    title: str,
    message: str,
    details: str = "",
    confirm_form: str = "",
    company: str = "pixelforge",
) -> dict[str, Any]:
    """Generate a clean HTML response for API Gateway."""
    color = "#10B981" if status_code == 200 else ("#F59E0B" if status_code == 409 else "#EF4444")
    icon = "✓" if status_code == 200 and not confirm_form else ("⚠" if confirm_form or status_code == 409 else "✕")
    company_title = company.title() if company else "PixelForge"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} — {company_title} FinOps</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0F172A; color: #F8FAFC; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; box-sizing: border-box; }}
        .card {{ background-color: #1E293B; border-radius: 12px; padding: 40px; width: 100%; max-width: 520px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); text-align: center; border: 1px solid #334155; }}
        .icon {{ font-size: 48px; color: {color}; margin-bottom: 16px; font-weight: bold; }}
        h1 {{ margin: 0 0 12px 0; font-size: 22px; font-weight: 600; }}
        p {{ color: #94A3B8; font-size: 15px; line-height: 1.5; margin-bottom: 20px; }}
        .details {{ background-color: #0F172A; border-radius: 8px; padding: 16px; text-align: left; font-family: monospace; font-size: 13px; color: #38BDF8; overflow-x: auto; white-space: pre-wrap; line-height: 1.6; margin-bottom: 24px; border: 1px solid #1E293B; }}
        .footer {{ margin-top: 28px; font-size: 12px; color: #64748B; }}
        .btn-confirm {{ background-color: #10B981; color: white; border: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 15px; cursor: pointer; transition: background 0.2s; }}
        .btn-confirm:hover {{ background-color: #059669; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">{icon}</div>
        <h1>{title}</h1>
        <p>{message}</p>
        {f'<div class="details">{details}</div>' if details else ''}
        {confirm_form}
        <div class="footer">{company_title} Studios FinOps Auto-Remediation System</div>
    </div>
</body>
</html>"""

    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": html,
    }


def parse_parameters(event: dict[str, Any]) -> dict[str, str]:
    """Extract parameters from query string or body."""
    params: dict[str, str] = {}
    if event.get("queryStringParameters"):
        params.update(event["queryStringParameters"])
    elif event.get("rawQueryString"):
        for k, v in parse_qs(event["rawQueryString"]).items():
            params[k] = v[0] if v else ""

    body = event.get("body")
    # Lambda Function URLs deliver form posts base64-encoded (isBase64Encoded=true).
    if body and event.get("isBase64Encoded") and isinstance(body, str):
        try:
            body = base64.b64decode(body).decode("utf-8")
        except Exception:
            logger.warning("Could not base64-decode request body")
            body = ""
    if body:
        if isinstance(body, dict):
            params.update({k: str(v) for k, v in body.items()})
        elif isinstance(body, str):
            try:
                # Try JSON
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    params.update({k: str(v) for k, v in json_data.items()})
            except Exception:
                # Try form urlencoded
                form_data = parse_qs(body)
                for k, v in form_data.items():
                    params[k] = v[0] if v else ""
    return params


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """API Gateway & Lambda entry point for two-step human approval.

    - GET: Displays confirmation review form with resource metadata.
    - POST: Atomically consumes approval token in DynamoDB and triggers remediation.
    """
    config = get_config()
    company = config.company

    # Determine HTTP Method
    http_method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    ).upper()

    params = parse_parameters(event)
    resource_id = params.get("resource_id", "").strip()
    action = params.get("action", "").strip().upper()
    expires_str = params.get("expires", "").strip()
    token = params.get("token", "").strip()

    if not all([resource_id, action, expires_str, token]):
        return build_html_response(
            status_code=400,
            title="Missing Parameters",
            message="The approval URL is incomplete or corrupted.",
            company=company,
        )

    try:
        expires_at_epoch = int(expires_str)
    except ValueError:
        return build_html_response(
            status_code=400,
            title="Invalid Expiry Format",
            message="The expiry timestamp in the URL is invalid.",
            company=company,
        )

    # Fetch secret and verify HMAC token
    secret_key = get_hmac_secret(config)
    is_valid = verify_approval_token(
        resource_id=resource_id,
        action=action,
        expires_at_epoch=expires_at_epoch,
        token=token,
        secret_key=secret_key,
    )

    if not is_valid:
        logger.warning("Invalid or expired approval token attempt for resource %s", resource_id)
        return build_html_response(
            status_code=403,
            title="Approval Failed",
            message="The approval link is invalid or has expired (links expire after 48 hours).",
            company=company,
        )

    # Re-fetch live resource metadata from AWS (N1 fix: Fail closed on describe failure)
    resource_type = "ec2" if resource_id.startswith("i-") else "ebs"
    ec2_client = boto3.client("ec2", region_name=config.region)
    tags: dict[str, str] = {}
    instance_type = "t3.micro"

    try:
        if resource_type == "ec2":
            res = ec2_client.describe_instances(InstanceIds=[resource_id])
            reservations = res.get("Reservations", [])
            if not reservations or not reservations[0].get("Instances"):
                return build_html_response(
                    status_code=404,
                    title="Resource Not Found",
                    message=f"EC2 instance {resource_id} does not exist in region {config.region}.",
                    company=company,
                )
            inst = reservations[0]["Instances"][0]
            instance_type = inst.get("InstanceType", "t3.micro")
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        else:
            res = ec2_client.describe_volumes(VolumeIds=[resource_id])
            volumes = res.get("Volumes", [])
            if not volumes:
                return build_html_response(
                    status_code=404,
                    title="Resource Not Found",
                    message=f"EBS volume {resource_id} does not exist in region {config.region}.",
                    company=company,
                )
            vol = volumes[0]
            tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
    except Exception as e:
        logger.error("Could not fetch live resource tags for %s: %s", resource_id, e)
        return build_html_response(
            status_code=404,
            title="Resource Inaccessible",
            message=f"Failed to verify live AWS resource {resource_id}: {str(e)}",
            company=company,
        )

    finding = Finding(
        resource_id=resource_id,
        resource_type=resource_type,
        idle_duration_hours=0.0,
        tags=tags,
        instance_type=instance_type,
    )

    # Enforce assert_actionable under mode='approved' (N3 fix)
    try:
        assert_actionable(finding, config=config, mode="approved")
    except ValueError as guard_err:
        logger.warning("assert_actionable guard rejected approval for %s: %s", resource_id, guard_err)
        return build_html_response(
            status_code=400,
            title="Safety Guard Violation",
            message=f"Action rejected by safety guard: {str(guard_err)}",
            company=company,
        )

    # Check if token was already consumed in DynamoDB (N4 replay protection)
    ddb_client = boto3.client("dynamodb", region_name=config.region)
    table_name = config.audit_table_name
    token_sort_key = f"APPROVAL_TOKEN#{token}"

    try:
        check_resp = ddb_client.get_item(
            TableName=table_name,
            Key={
                "tenant_id": {"S": config.tenant_id},
                "log_id": {"S": token_sort_key},
            },
        )
        if check_resp.get("Item"):
            return build_html_response(
                status_code=409,
                title="Action Already Executed",
                message=f"Remediation for resource {resource_id} has already been approved and executed. This link cannot be reused.",
                details=f"Resource ID: {resource_id}\nAction: {action}\nToken Status: CONSUMED",
                company=company,
            )
    except Exception as ddb_check_err:
        logger.debug("Approval token check exception: %s", ddb_check_err)

    # -------------------------------------------------------------------------
    # STEP 1: GET Request -> Render Review & Confirmation Form
    # -------------------------------------------------------------------------
    if http_method == "GET":
        env_val = tags.get("env", "unknown")
        owner_val = tags.get("owner", "unassigned")
        details_text = (
            f"Resource ID:  {resource_id}\n"
            f"Type:         {resource_type.upper()}\n"
            f"Environment:  {env_val.upper()}\n"
            f"Owner:        {owner_val}\n"
            f"Action:       {action}\n"
            f"Token Expiry: {datetime.fromtimestamp(expires_at_epoch, timezone.utc).isoformat()}"
        )
        confirm_form_html = f"""
        <form method="POST" action="/approve" style="margin-top: 20px;">
            <input type="hidden" name="resource_id" value="{resource_id}">
            <input type="hidden" name="action" value="{action}">
            <input type="hidden" name="expires" value="{expires_str}">
            <input type="hidden" name="token" value="{token}">
            <button type="submit" class="btn-confirm">Confirm Remediation</button>
        </form>
        """
        return build_html_response(
            status_code=200,
            title="Confirm Remediation Approval",
            message=f"Please review the resource details below and click confirm to execute {action}.",
            details=details_text,
            confirm_form=confirm_form_html,
            company=company,
        )

    # -------------------------------------------------------------------------
    # STEP 2: POST Request -> Atomic Token Consumption & Execution
    # -------------------------------------------------------------------------
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        ddb_client.put_item(
            TableName=table_name,
            Item={
                "tenant_id": {"S": config.tenant_id},
                "log_id": {"S": token_sort_key},
                "resource_id": {"S": resource_id},
                "action": {"S": action},
                "consumed_at": {"S": now_iso},
                "ttl": {"N": str(expires_at_epoch)},
            },
            ConditionExpression="attribute_not_exists(log_id)",
        )
    except Exception as cond_err:
        if "ConditionalCheckFailedException" in str(type(cond_err)) or "ConditionalCheckFailedException" in str(cond_err):
            return build_html_response(
                status_code=409,
                title="Action Already Executed",
                message=f"Remediation for resource {resource_id} has already been approved and executed. Replay attempts are rejected.",
                details=f"Resource ID: {resource_id}\nAction: {action}\nToken Status: CONSUMED",
                company=company,
            )
        logger.error("Failed recording approval token in DynamoDB: %s", cond_err)
        raise

    # Execute remediation in mode='approved'
    try:
        rem_res = remediate_resource(
            finding,
            config=config,
            ec2_client=ec2_client,
            mode="approved",
        )
    except Exception as e:
        logger.error("Failed to remediate resource %s upon approval: %s", resource_id, e)
        # Nothing was changed, so release the single-use link: the approver can retry after the cause is fixed.
        try:
            ddb_client.delete_item(
                TableName=table_name,
                Key={"tenant_id": {"S": config.tenant_id}, "log_id": {"S": token_sort_key}},
            )
        except Exception as release_err:  # pragma: no cover - best effort
            logger.warning("Could not release approval token for %s: %s", resource_id, release_err)
        return build_html_response(
            status_code=500,
            title="Execution Error",
            message=f"An error occurred while remediating {resource_id}: {str(e)}",
            details="No change was made and this approval link was NOT used up. Fix the cause and open the link again.",
            company=company,
        )

    try:
        evaluation = EvaluationResult(
            finding=finding,
            confidence=Confidence.HIGH,
            risk=Risk.HIGH,
            decision=Decision.AUTO_REMEDIATE,
            reason="Human manager approved remediation via HMAC email link",
        )
        write_audit_log(
            finding=finding,
            evaluation=evaluation,
            action_taken="HUMAN_APPROVED_REMEDIATION",
            config=config,
        )

        dry_prefix = "[DRY RUN] " if config.dry_run else ""
        return build_html_response(
            status_code=200,
            title="Remediation Approved",
            message=f"{dry_prefix}Successfully executed action '{action}' on resource {resource_id}.",
            details=f"Resource ID: {resource_id}\nAction: {action}\nProvenance: Verified HMAC Email Token\nExecution: {rem_res.get('action_detail', 'Completed')}",
            company=company,
        )

    except Exception as e:
        logger.error("Failed to remediate resource %s upon approval: %s", resource_id, e)
        return build_html_response(
            status_code=500,
            title="Execution Error",
            message=f"An error occurred while remediating {resource_id}: {str(e)}",
            company=company,
        )
