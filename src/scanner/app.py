"""
Scanner Lambda Handler — orchestrates EC2 and EBS scanning.

Invoked by EventBridge schedule. Scans for idle resources, evaluates each
finding through the policy engine, and returns grouped results for
downstream processing (remediation, escalation, audit logging).
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from src.audit.writer import write_audit_log
from src.config import Config, get_config
from src.escalation.handler import send_escalation_notification
from src.metrics import publish_finops_metrics
from src.policy_engine import (
    CircuitBreaker,
    Decision,
    EvaluationResult,
    evaluate,
)
from src.remediation.handler import remediate_resource
from src.scanner import ec2_scanner, ebs_scanner

logger = logging.getLogger(__name__)

# Structured JSON logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}',
)


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Scanner Lambda entry point.

    Args:
        event: EventBridge scheduled event (ignored for scanning).
        context: Lambda context object (optional).

    Returns:
        Summary dict with run_id, findings counts, and grouped results.
    """
    config = get_config()
    run_id = str(uuid.uuid4())

    logger.info(
        "Scanner run starting: run_id=%s, dry_run=%s, demo_mode=%s, company=%s",
        run_id,
        config.dry_run,
        config.demo_mode,
        config.company,
    )

    # -----------------------------------------------------------------------
    # Scan for idle resources
    # -----------------------------------------------------------------------
    ec2_findings = ec2_scanner.scan(config=config)
    ebs_findings = ebs_scanner.scan(config=config)
    all_findings = ec2_findings + ebs_findings

    logger.info(
        "Scan complete: %d EC2 findings, %d EBS findings",
        len(ec2_findings),
        len(ebs_findings),
    )

    # -----------------------------------------------------------------------
    # Evaluate each finding through the policy engine
    # -----------------------------------------------------------------------
    circuit_breaker = CircuitBreaker(max_actions=config.max_remediations_per_run)

    results: list[dict[str, Any]] = []
    counts = {
        "total": len(all_findings),
        "auto_remediate": 0,
        "escalate": 0,
        "log_only": 0,
        "skip": 0,
        "failed": 0,
        "circuit_breaker_tripped": False,
    }
    estimated_savings = 0.0
    evaluated_actions: list[tuple[Any, EvaluationResult]] = []

    for finding in all_findings:
        eval_result: EvaluationResult = evaluate(
            finding=finding,
            ec2_idle_window_hours=config.ec2_idle_window_hours,
            ec2_cpu_threshold=config.ec2_cpu_threshold,
            ebs_unattached_hours=config.ebs_unattached_hours,
            scope_tag_key=config.scope_tag_key,
            scope_tag_value=config.scope_tag_value,
            company=config.company,
        )

        # Apply circuit breaker
        final_decision, just_tripped = circuit_breaker.check_and_increment(
            eval_result.decision
        )
        if just_tripped:
            counts["circuit_breaker_tripped"] = True
            logger.warning("Circuit breaker TRIPPED at run_id=%s", run_id)

        # Update decision if circuit breaker changed it
        if final_decision != eval_result.decision:
            reason = f"Circuit breaker override: {eval_result.decision.value} → {final_decision.value}"
            eval_result = EvaluationResult(
                finding=eval_result.finding,
                confidence=eval_result.confidence,
                risk=eval_result.risk,
                decision=final_decision,
                reason=reason,
            )

        # Count decisions
        decision_key = eval_result.decision.value.lower()
        if decision_key in counts:
            counts[decision_key] += 1

        # Track savings for remediated / escalated resources
        if eval_result.decision in (Decision.AUTO_REMEDIATE, Decision.ESCALATE):
            estimated_savings += finding.estimated_monthly_cost

        results.append(
            {
                "run_id": run_id,
                "resource_id": finding.resource_id,
                "resource_type": finding.resource_type,
                "decision": eval_result.decision.value,
                "confidence": eval_result.confidence.value,
                "risk": eval_result.risk.value,
                "reason": eval_result.reason,
                "estimated_monthly_cost": finding.estimated_monthly_cost,
                "tags": finding.tags,
                "idle_duration_hours": finding.idle_duration_hours,
                "avg_cpu": finding.avg_cpu,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        evaluated_actions.append((finding, eval_result))

    # -----------------------------------------------------------------------
    # Orchestrate downstream actions (Remediation, Escalation, Audit Logging)
    # -----------------------------------------------------------------------
    remediation_actions: list[dict[str, Any]] = []
    escalation_actions: list[dict[str, Any]] = []
    realized_savings = 0.0

    for finding_obj, eval_res in evaluated_actions:
        try:
            if eval_res.decision == Decision.AUTO_REMEDIATE:
                rem_res = remediate_resource(finding_obj, config=config)
                remediation_actions.append(rem_res)
                if not config.dry_run and rem_res.get("status") != "FAILED":
                    realized_savings += finding_obj.estimated_monthly_cost
                action_name = "[DRY_RUN] AUTO_REMEDIATED" if config.dry_run else "AUTO_REMEDIATED"
                try:
                    write_audit_log(
                        finding=finding_obj,
                        evaluation=eval_res,
                        action_taken=action_name,
                        config=config,
                    )
                except Exception as log_err:
                    counts["failed"] += 1
                    logger.error("Audit log write failed for %s: %s", finding_obj.resource_id, log_err)

            elif eval_res.decision == Decision.ESCALATE:
                esc_res = send_escalation_notification(finding_obj, eval_res, config=config)
                escalation_actions.append(esc_res)

            elif eval_res.decision in (Decision.LOG_ONLY, Decision.SKIP):
                try:
                    write_audit_log(
                        finding=finding_obj,
                        evaluation=eval_res,
                        action_taken=eval_res.decision.value,
                        config=config,
                    )
                except Exception as log_err:
                    counts["failed"] += 1
                    logger.error("Audit log write failed for %s: %s", finding_obj.resource_id, log_err)

        except Exception as action_err:
            counts["failed"] += 1
            logger.error("Downstream action failed for %s (%s): %s", finding_obj.resource_id, eval_res.decision.value, action_err)

    # -----------------------------------------------------------------------
    # Build summary
    # -----------------------------------------------------------------------
    summary = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": config.dry_run,
        "demo_mode": config.demo_mode,
        "company": config.company,
        "counts": counts,
        "estimated_monthly_savings": round(estimated_savings, 2),
        "results": results,
        "remediations": remediation_actions,
        "escalations": escalation_actions,
    }

    logger.info(
        "Scanner run complete: run_id=%s, findings=%d, auto=%d, escalate=%d, log_only=%d, skip=%d, savings=$%.2f",
        run_id,
        counts["total"],
        counts["auto_remediate"],
        counts["escalate"],
        counts["log_only"],
        counts["skip"],
        estimated_savings,
    )

    # -----------------------------------------------------------------------
    # Publish custom CloudWatch metrics (<= 8 metrics, zero dimensions)
    # -----------------------------------------------------------------------
    metrics_payload = {
        "ResourcesScanned": counts["total"],
        "IdleEC2Detected": len(ec2_findings),
        "UnattachedEBSDetected": len(ebs_findings),
        "AutoRemediatedActions": counts["auto_remediate"],
        "EscalatedActions": counts["escalate"],
        "EstimatedMonthlySavings": round(estimated_savings, 2),
        "RealizedMonthlySavings": round(realized_savings, 2),
        "RemediationFailures": counts["failed"],
    }
    try:
        publish_finops_metrics(metrics_payload, region=config.region)
    except Exception as cw_err:
        logger.error("Failed publishing CloudWatch metrics: %s", cw_err)

    return summary
