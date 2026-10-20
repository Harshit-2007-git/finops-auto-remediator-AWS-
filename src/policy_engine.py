"""
Policy Engine for FinOps Auto-Remediation.

Pure Python module — no AWS SDK calls. Evaluates findings against the
decision table and per-company overrides to produce remediation decisions.

Decision Table:
    HIGH confidence + LOW risk  → AUTO_REMEDIATE
    HIGH confidence + HIGH risk → ESCALATE
    LOW confidence  + LOW risk  → ESCALATE
    LOW confidence  + HIGH risk → LOG_ONLY

Safety guards (evaluated before the decision table):
    1. Scope guard:  resource MUST have tag Project=finops-demo → else SKIP
    2. Keep guard:   keep=true → force LOG_ONLY
    3. Prod guard:   env=prod → never AUTO_REMEDIATE (override to ESCALATE)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.config import load_company_policy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Confidence(Enum):
    HIGH = "HIGH"
    LOW = "LOW"


class Risk(Enum):
    HIGH = "HIGH"
    LOW = "LOW"


class Decision(Enum):
    AUTO_REMEDIATE = "AUTO_REMEDIATE"
    ESCALATE = "ESCALATE"
    LOG_ONLY = "LOG_ONLY"
    SKIP = "SKIP"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """Represents a single waste-detection finding."""

    resource_id: str
    resource_type: str  # "ec2" or "ebs"
    idle_duration_hours: float
    avg_cpu: float | None = None  # None for EBS
    tags: dict[str, str] = field(default_factory=dict)
    estimated_monthly_cost: float = 0.0
    instance_type: str = "t3.micro"

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "idle_duration_hours": self.idle_duration_hours,
            "avg_cpu": self.avg_cpu,
            "tags": self.tags,
            "estimated_monthly_cost": self.estimated_monthly_cost,
            "instance_type": self.instance_type,
        }


# ---------------------------------------------------------------------------
# Evaluation result
# ---------------------------------------------------------------------------
@dataclass
class EvaluationResult:
    """Result of evaluating a finding against the policy engine."""

    finding: Finding
    confidence: Confidence
    risk: Risk
    decision: Decision
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Convert evaluation result to dictionary representation."""
        return {
            "finding": self.finding.to_dict(),
            "confidence": self.confidence.value,
            "risk": self.risk.value,
            "decision": self.decision.value,
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Core scoring functions
# ---------------------------------------------------------------------------
def compute_confidence(
    finding: Finding,
    ec2_idle_window_hours: float,
    ec2_cpu_threshold: float,
    ebs_unattached_hours: float,
) -> Confidence:
    """Compute confidence level based on idle duration and CPU usage.

    EC2: HIGH if idle_duration >= window AND avg_cpu < threshold.
    EBS: HIGH if idle_duration >= threshold.
    """
    if finding.resource_type == "ec2":
        if (
            finding.idle_duration_hours >= ec2_idle_window_hours
            and finding.avg_cpu is not None
            and finding.avg_cpu < ec2_cpu_threshold
        ):
            return Confidence.HIGH
        return Confidence.LOW

    if finding.resource_type == "ebs":
        if finding.idle_duration_hours >= ebs_unattached_hours:
            return Confidence.HIGH
        return Confidence.LOW

    # Unknown resource type → LOW confidence
    return Confidence.LOW


def compute_risk(finding: Finding) -> Risk:
    """Compute risk level based on resource tags.

    HIGH risk if: env=prod, keep=true, missing owner tag, missing env tag.
    LOW risk if: env=dev or env=qa with owner present.
    """
    tags = finding.tags
    env = tags.get("env", "").lower()
    keep = tags.get("keep", "").lower()
    owner = tags.get("owner", "")

    # Any of these conditions → HIGH risk
    if env == "prod":
        return Risk.HIGH
    if keep == "true":
        return Risk.HIGH
    if not owner:
        return Risk.HIGH
    if not env:
        return Risk.HIGH

    return Risk.LOW


# ---------------------------------------------------------------------------
# Decision table
# ---------------------------------------------------------------------------
DECISION_TABLE: dict[tuple[Confidence, Risk], Decision] = {
    (Confidence.HIGH, Risk.LOW): Decision.AUTO_REMEDIATE,
    (Confidence.HIGH, Risk.HIGH): Decision.ESCALATE,
    (Confidence.LOW, Risk.LOW): Decision.ESCALATE,
    (Confidence.LOW, Risk.HIGH): Decision.LOG_ONLY,
}


def apply_decision_table(confidence: Confidence, risk: Risk) -> Decision:
    """Look up the decision from the confidence × risk matrix."""
    return DECISION_TABLE[(confidence, risk)]


# ---------------------------------------------------------------------------
# Per-company overrides
# ---------------------------------------------------------------------------
def apply_company_overrides(
    decision: Decision,
    finding: Finding,
    company: str,
) -> tuple[Decision, str]:
    """Apply per-company policy overrides.

    Returns:
        Tuple of (possibly modified decision, reason string).
    """
    policy = load_company_policy(company)
    overrides = policy.get("overrides", {})
    env_rules = overrides.get("env_rules", {})

    env = finding.tags.get("env", "").lower()
    if env in env_rules:
        rule = env_rules[env]
        if rule.get("always_escalate") and decision == Decision.AUTO_REMEDIATE:
            return Decision.ESCALATE, f"Company policy: {env} always escalates"
        if not rule.get("allow_auto_remediate") and decision == Decision.AUTO_REMEDIATE:
            return Decision.ESCALATE, f"Company policy: {env} does not allow auto-remediation"

    return decision, "Decision table"


# ---------------------------------------------------------------------------
# Safety guards
# ---------------------------------------------------------------------------
def check_safety_guards(
    finding: Finding,
    scope_tag_key: str,
    scope_tag_value: str,
) -> tuple[Decision | None, str]:
    """Check safety guards before the decision table.

    Returns:
        (Decision, reason) if a guard fires, or (None, "") if no guard fires.
    """
    tags = finding.tags

    # Guard 1: Scope tag must be present and match (if scope_tag_key is specified)
    if scope_tag_key and tags.get(scope_tag_key) != scope_tag_value:
        return Decision.SKIP, f"Missing or wrong scope tag {scope_tag_key}={scope_tag_value}"

    # Guard 2: keep=true → LOG_ONLY
    if tags.get("keep", "").lower() == "true":
        return Decision.LOG_ONLY, "Resource tagged keep=true"

    # Guard 3: env=prod → never AUTO_REMEDIATE (handled later, but we flag it)
    # This is handled by the decision table + company overrides, so no guard here

    return None, ""


# ---------------------------------------------------------------------------
# Main evaluation function
# ---------------------------------------------------------------------------
def evaluate(
    finding: Finding,
    ec2_idle_window_hours: float = 168.0,  # 7 days
    ec2_cpu_threshold: float = 5.0,
    ebs_unattached_hours: float = 720.0,  # 30 days
    scope_tag_key: str = "Project",
    scope_tag_value: str = "finops-demo",
    company: str = "pixelforge",
) -> EvaluationResult:
    """Evaluate a single finding through the full policy pipeline.

    Pipeline:
        1. Safety guards (scope tag, keep=true)
        2. Confidence scoring
        3. Risk scoring
        4. Decision table lookup
        5. Per-company overrides
        6. Prod guard (env=prod never AUTO_REMEDIATE)

    Args:
        finding: The waste-detection finding to evaluate.
        ec2_idle_window_hours: EC2 idle window threshold in hours.
        ec2_cpu_threshold: CPU utilization threshold (percent).
        ebs_unattached_hours: EBS unattached threshold in hours.
        scope_tag_key: Tag key for scope filtering.
        scope_tag_value: Tag value for scope filtering.
        company: Company identifier for policy overrides.

    Returns:
        EvaluationResult with confidence, risk, decision, and reason.
    """
    # Step 1: Safety guards
    guard_decision, guard_reason = check_safety_guards(
        finding, scope_tag_key, scope_tag_value
    )
    if guard_decision is not None:
        logger.info(
            "Safety guard fired for %s: %s → %s",
            finding.resource_id,
            guard_reason,
            guard_decision.value,
        )
        # For SKIP, confidence and risk are not meaningful
        conf = Confidence.LOW
        risk = Risk.HIGH
        if guard_decision == Decision.SKIP:
            return EvaluationResult(
                finding=finding,
                confidence=conf,
                risk=risk,
                decision=Decision.SKIP,
                reason=guard_reason,
            )
        # For keep=true guard → LOG_ONLY, still compute confidence/risk for audit
        conf = compute_confidence(
            finding, ec2_idle_window_hours, ec2_cpu_threshold, ebs_unattached_hours
        )
        risk = compute_risk(finding)
        return EvaluationResult(
            finding=finding,
            confidence=conf,
            risk=risk,
            decision=guard_decision,
            reason=guard_reason,
        )

    # Step 2–3: Scoring
    confidence = compute_confidence(
        finding, ec2_idle_window_hours, ec2_cpu_threshold, ebs_unattached_hours
    )
    risk = compute_risk(finding)

    # Step 4: Decision table
    decision = apply_decision_table(confidence, risk)

    # Step 5: Company overrides
    decision, reason = apply_company_overrides(decision, finding, company)

    # Step 6: Final prod guard — env=prod can never be AUTO_REMEDIATE
    env = finding.tags.get("env", "").lower()
    if env == "prod" and decision == Decision.AUTO_REMEDIATE:
        decision = Decision.ESCALATE
        reason = "Prod guard: env=prod cannot be auto-remediated"

    logger.info(
        "Evaluated %s: confidence=%s, risk=%s → %s (%s)",
        finding.resource_id,
        confidence.value,
        risk.value,
        decision.value,
        reason,
    )

    return EvaluationResult(
        finding=finding,
        confidence=confidence,
        risk=risk,
        decision=decision,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------
class CircuitBreaker:
    """Tracks remediation actions per run and trips after the limit.

    When tripped, AUTO_REMEDIATE decisions are converted to ESCALATE.
    """

    def __init__(self, max_actions: int = 5):
        self.max_actions = max_actions
        self._count = 0
        self._tripped = False

    @property
    def count(self) -> int:
        return self._count

    @property
    def tripped(self) -> bool:
        return self._tripped

    def check_and_increment(self, decision: Decision) -> tuple[Decision, bool]:
        """Check if the circuit breaker allows this action.

        Args:
            decision: The proposed decision.

        Returns:
            Tuple of (possibly modified decision, whether breaker tripped on THIS call).
        """
        if decision != Decision.AUTO_REMEDIATE:
            return decision, False

        if self._count >= self.max_actions:
            if not self._tripped:
                self._tripped = True
                logger.warning(
                    "Circuit breaker TRIPPED at %d actions (limit: %d)",
                    self._count,
                    self.max_actions,
                )
                return Decision.ESCALATE, True
            return Decision.ESCALATE, False

        self._count += 1
        return Decision.AUTO_REMEDIATE, False
