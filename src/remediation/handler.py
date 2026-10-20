"""
Remediation Handler module — executes automated and approved resource cleanup actions.

EC2: Stops idle instance and adds tag FinOpsStatus=StoppedByFinOps
EBS: Creates a safety backup snapshot and deletes unattached volume

Respects DRY_RUN flag — when dry_run=true, API state-changing calls are skipped.
Writes KMS-encrypted audit log entries for every executed action.
Enforces assert_actionable safety guard with strict mode separation ('auto' vs 'approved').
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import boto3

from src.audit.writer import write_audit_log
from src.config import Config, get_config
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk, evaluate

logger = logging.getLogger(__name__)


def assert_actionable(
    finding: Finding,
    config: Config | None = None,
    mode: str = "auto",
) -> None:
    """Validate that a resource finding satisfies safety guards before remediation.

    Args:
        finding: Resource finding to validate.
        config: Application configuration (defaults to get_config()).
        mode: Remediation mode ('auto' or 'approved').
              - 'auto': Strictly forbids remediation of prod environment resources.
              - 'approved': Allows prod resources if verified by human approval,
                            but strictly refuses 'keep=true' or missing scope tag.

    Raises:
        ValueError: If resource fails safety guards.
    """
    if config is None:
        config = get_config()

    tags = finding.tags or {}

    # Guard 1: Scope tag check (Project=finops-demo)
    if config.scope_tag_key:
        scope_val = tags.get(config.scope_tag_key)
        if not scope_val or scope_val != config.scope_tag_value:
            raise ValueError(
                f"Resource {finding.resource_id} missing required scope tag "
                f"'{config.scope_tag_key}={config.scope_tag_value}'. Out of scope."
            )

    # Guard 2: keep=true override (strictly forbids remediation in both auto and approved modes)
    keep_val = str(tags.get("keep", "")).lower()
    if keep_val == "true":
        raise ValueError(
            f"Resource {finding.resource_id} has 'keep=true' tag. "
            "Safety guard strictly forbids remediation."
        )

    # Guard 3: Production environment guard
    env = str(tags.get("env", "")).lower()
    if mode == "auto" and env == "prod":
        raise ValueError(
            f"Resource {finding.resource_id} is in production (env=prod). "
            "Automatic remediation is forbidden. Requires human manager escalation."
        )


def remediate_resource(
    finding: Finding,
    config: Config | None = None,
    ec2_client: Any = None,
    mode: str = "auto",
) -> dict[str, Any]:
    """Execute remediation action for a single resource.

    Args:
        finding: Resource finding to remediate.
        config: Application config (defaults to get_config()).
        ec2_client: boto3 EC2 client (created if None).
        mode: Remediation mode ('auto' or 'approved').

    Returns:
        Dict describing remediation status, actions taken, and snapshot details.

    Raises:
        ValueError: If resource is not actionable or unsupported resource type.
    """
    if config is None:
        config = get_config()
    if ec2_client is None:
        ec2_client = boto3.client("ec2", region_name=config.region)

    # Enforce safety guards before any action
    assert_actionable(finding, config=config, mode=mode)

    resource_id = finding.resource_id
    resource_type = finding.resource_type
    now_iso = datetime.now(timezone.utc).isoformat()
    dry_run = config.dry_run

    result: dict[str, Any] = {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "mode": mode,
        "dry_run": dry_run,
        "timestamp": now_iso,
        "status": "SUCCESS",
    }

    if resource_type == "ec2":
        logger.info("Remediating EC2 instance %s (mode=%s, dry_run=%s)", resource_id, mode, dry_run)
        tags = [
            {"Key": "FinOpsStatus", "Value": "StoppedByFinOps"},
            {"Key": "FinOpsStoppedAt", "Value": now_iso},
            {"Key": "FinOpsRemediationMode", "Value": mode},
        ]
        if not dry_run:
            ec2_client.create_tags(Resources=[resource_id], Tags=tags)
            ec2_client.stop_instances(InstanceIds=[resource_id])
            logger.info("Successfully stopped EC2 instance %s", resource_id)
            result["action_detail"] = f"Stopped instance {resource_id}"
        else:
            logger.info("[DRY RUN] Would stop EC2 instance %s and set tags", resource_id)
            result["action_detail"] = f"[DRY RUN] Would stop instance {resource_id}"

    elif resource_type == "ebs":
        logger.info("Remediating EBS volume %s (mode=%s, dry_run=%s)", resource_id, mode, dry_run)
        snapshot_desc = f"Pre-deletion safety backup for {resource_id} by FinOpsAutoRemediation ({mode})"
        tags = [
            {"Key": "Name", "Value": f"snapshot-{resource_id}"},
            {"Key": "Project", "Value": config.scope_tag_value},
            {"Key": "FinOpsStatus", "Value": "CreatedBeforeDelete"},
            {"Key": "SourceVolumeId", "Value": resource_id},
            {"Key": "FinOpsRemediationMode", "Value": mode},
        ]

        if not dry_run:
            # Step 1: Create safety snapshot
            snap_resp = ec2_client.create_snapshot(
                VolumeId=resource_id,
                Description=snapshot_desc,
                TagSpecifications=[{"ResourceType": "snapshot", "Tags": tags}],
            )
            snapshot_id = snap_resp.get("SnapshotId", "unknown-snap")
            logger.info("Created safety snapshot %s for volume %s", snapshot_id, resource_id)
            result["snapshot_id"] = snapshot_id

            # Step 2: Delete unattached volume
            ec2_client.delete_volume(VolumeId=resource_id)
            logger.info("Successfully deleted volume %s", resource_id)
            result["action_detail"] = f"Created snapshot {snapshot_id} and deleted volume {resource_id}"
        else:
            logger.info("[DRY RUN] Would snapshot and delete volume %s", resource_id)
            result["action_detail"] = f"[DRY RUN] Would snapshot and delete volume {resource_id}"

    else:
        raise ValueError(f"Unsupported resource type for remediation: {resource_type}")

    return result


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Lambda handler for automated remediation.

    Accepts payload with 'findings' array and executes remediation + audit logging.

    Args:
        event: Dict containing 'findings' list.
        context: Lambda context.

    Returns:
        Summary dict of remediated resources.
    """
    config = get_config()
    findings_raw = event.get("findings", [])
    remediated_results = []

    logger.info("Remediation handler invoked with %d findings", len(findings_raw))

    for f_dict in findings_raw:
        finding = Finding(
            resource_id=f_dict["resource_id"],
            resource_type=f_dict["resource_type"],
            idle_duration_hours=f_dict.get("idle_duration_hours", 0.0),
            avg_cpu=f_dict.get("avg_cpu"),
            tags=f_dict.get("tags", {}),
            estimated_monthly_cost=f_dict.get("estimated_monthly_cost", 0.0),
            instance_type=f_dict.get("instance_type", "t3.micro"),
        )

        # Re-evaluate policy to ensure safety rules and tags still permit auto-remediation
        eval_result = evaluate(
            finding=finding,
            ec2_idle_window_hours=config.ec2_idle_window_hours,
            ec2_cpu_threshold=config.ec2_cpu_threshold,
            ebs_unattached_hours=config.ebs_unattached_hours,
            scope_tag_key=config.scope_tag_key,
            scope_tag_value=config.scope_tag_value,
            company=config.company,
        )

        if eval_result.decision != Decision.AUTO_REMEDIATE:
            logger.warning(
                "Skipping remediation for %s: evaluated decision is %s (reason: %s)",
                finding.resource_id,
                eval_result.decision.value,
                eval_result.reason,
            )
            continue

        # Execute remediation in mode="auto"
        try:
            rem_res = remediate_resource(finding, config=config, mode="auto")
        except ValueError as guard_err:
            logger.warning("assert_actionable guard blocked %s: %s", finding.resource_id, guard_err)
            continue

        # Write audit log
        action_name = "[DRY_RUN] AUTO_REMEDIATED" if config.dry_run else "AUTO_REMEDIATED"
        write_audit_log(
            finding=finding,
            evaluation=eval_result,
            action_taken=action_name,
            config=config,
        )

        remediated_results.append(rem_res)

    return {
        "status": "COMPLETED",
        "dry_run": config.dry_run,
        "count": len(remediated_results),
        "results": remediated_results,
    }
