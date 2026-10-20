"""
Tests for the Policy Engine — Milestone M1.

Covers:
    - All four decision-table quadrants (HIGH/LOW × HIGH/LOW)
    - Scope-tag safety guard (SKIP)
    - keep=true safety guard (LOG_ONLY)
    - Prod override (never AUTO_REMEDIATE)
    - EBS confidence scoring
    - PixelForge company policy loading
    - Circuit breaker (max 5 actions)
"""

from __future__ import annotations

import pytest

from src.policy_engine import (
    CircuitBreaker,
    Confidence,
    Decision,
    EvaluationResult,
    Finding,
    Risk,
    apply_decision_table,
    compute_confidence,
    compute_risk,
    evaluate,
)
from src.config import load_company_policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_finding(
    resource_type: str = "ec2",
    idle_hours: float = 200.0,
    avg_cpu: float | None = 2.0,
    env: str = "dev",
    keep: str | None = None,
    project: str = "finops-demo",
    owner: str = "alice@pixelforge.io",
    resource_id: str = "i-abc123",
) -> Finding:
    """Create a Finding with sensible defaults for testing."""
    tags: dict[str, str] = {
        "Project": project,
        "env": env,
        "owner": owner,
    }
    if keep is not None:
        tags["keep"] = keep
    return Finding(
        resource_id=resource_id,
        resource_type=resource_type,
        idle_duration_hours=idle_hours,
        avg_cpu=avg_cpu,
        tags=tags,
        estimated_monthly_cost=7.49,
    )


# Shared evaluation kwargs matching production defaults
EVAL_KWARGS = dict(
    ec2_idle_window_hours=168.0,  # 7 days
    ec2_cpu_threshold=5.0,
    ebs_unattached_hours=720.0,  # 30 days
    scope_tag_key="Project",
    scope_tag_value="finops-demo",
    company="pixelforge",
)


# ===================================================================
# Decision Table Quadrants
# ===================================================================
class TestDecisionTable:
    """Test all four quadrants of the confidence × risk decision table."""

    def test_high_conf_low_risk_auto_remediate(self):
        """HIGH confidence + LOW risk → AUTO_REMEDIATE.

        Scenario: dev EC2 instance, idle for 200h (> 168h threshold),
        avg CPU 2% (< 5% threshold), owner present, env=dev.
        """
        finding = _make_finding(
            env="dev", idle_hours=200.0, avg_cpu=2.0, owner="alice@pixelforge.io"
        )
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.confidence == Confidence.HIGH
        assert result.risk == Risk.LOW
        assert result.decision == Decision.AUTO_REMEDIATE

    def test_high_conf_high_risk_escalate(self):
        """HIGH confidence + HIGH risk → ESCALATE.

        Scenario: prod EC2 instance, idle for 200h, avg CPU 2%.
        env=prod triggers HIGH risk.
        """
        finding = _make_finding(env="prod", idle_hours=200.0, avg_cpu=2.0)
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.confidence == Confidence.HIGH
        assert result.risk == Risk.HIGH
        assert result.decision == Decision.ESCALATE

    def test_low_conf_low_risk_escalate(self):
        """LOW confidence + LOW risk → ESCALATE.

        Scenario: dev EC2 instance, idle for only 50h (< 168h threshold).
        Short idle duration → LOW confidence, env=dev + owner → LOW risk.
        """
        finding = _make_finding(env="dev", idle_hours=50.0, avg_cpu=2.0)
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.confidence == Confidence.LOW
        assert result.risk == Risk.LOW
        assert result.decision == Decision.ESCALATE

    def test_low_conf_high_risk_log_only(self):
        """LOW confidence + HIGH risk → LOG_ONLY.

        Scenario: prod EC2 instance, idle for only 50h (< 168h threshold).
        Short idle → LOW confidence, env=prod → HIGH risk.
        """
        finding = _make_finding(env="prod", idle_hours=50.0, avg_cpu=2.0)
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.confidence == Confidence.LOW
        assert result.risk == Risk.HIGH
        assert result.decision == Decision.LOG_ONLY


# ===================================================================
# Safety Guards
# ===================================================================
class TestSafetyGuards:
    """Test safety guard enforcement."""

    def test_scope_tag_guard_skip(self):
        """Resources without Project=finops-demo are SKIPPED entirely."""
        finding = _make_finding(project="other-project")
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.decision == Decision.SKIP
        assert "scope tag" in result.reason.lower()

    def test_missing_scope_tag_skip(self):
        """Resources with no Project tag are SKIPPED."""
        finding = Finding(
            resource_id="i-noproject",
            resource_type="ec2",
            idle_duration_hours=200.0,
            avg_cpu=1.0,
            tags={"env": "dev", "owner": "alice@pixelforge.io"},
            estimated_monthly_cost=7.49,
        )
        result = evaluate(finding, **EVAL_KWARGS)
        assert result.decision == Decision.SKIP

    def test_keep_true_always_log_only(self):
        """keep=true forces LOG_ONLY regardless of confidence/risk.

        Even a HIGH confidence + LOW risk finding (which would normally
        AUTO_REMEDIATE) is forced to LOG_ONLY.
        """
        finding = _make_finding(
            env="dev",
            idle_hours=200.0,
            avg_cpu=2.0,
            keep="true",
            owner="alice@pixelforge.io",
        )
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.decision == Decision.LOG_ONLY
        assert "keep=true" in result.reason.lower()

    def test_prod_override_no_auto_remediate(self):
        """env=prod can NEVER be AUTO_REMEDIATE.

        Even if risk scoring were LOW (hypothetically), the prod guard
        and company override ensure it becomes ESCALATE.
        """
        # Force a scenario where prod might try to auto-remediate
        # by using high confidence. The prod guard catches it.
        finding = _make_finding(env="prod", idle_hours=200.0, avg_cpu=1.0)
        result = evaluate(finding, **EVAL_KWARGS)

        assert result.decision in (Decision.ESCALATE, Decision.LOG_ONLY)
        assert result.decision != Decision.AUTO_REMEDIATE


# ===================================================================
# Confidence Scoring
# ===================================================================
class TestConfidenceScoring:
    """Test confidence computation logic."""

    def test_ec2_high_confidence(self):
        """EC2 idle long enough with low CPU → HIGH."""
        finding = _make_finding(idle_hours=200.0, avg_cpu=2.0)
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.HIGH

    def test_ec2_low_confidence_short_idle(self):
        """EC2 not idle long enough → LOW."""
        finding = _make_finding(idle_hours=100.0, avg_cpu=2.0)
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.LOW

    def test_ec2_low_confidence_high_cpu(self):
        """EC2 has high CPU (not really idle) → LOW."""
        finding = _make_finding(idle_hours=200.0, avg_cpu=50.0)
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.LOW

    def test_ebs_high_confidence(self):
        """EBS unattached longer than threshold → HIGH."""
        finding = _make_finding(
            resource_type="ebs",
            idle_hours=800.0,
            avg_cpu=None,
            resource_id="vol-abc123",
        )
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.HIGH

    def test_ebs_low_confidence(self):
        """EBS unattached shorter than threshold → LOW."""
        finding = _make_finding(
            resource_type="ebs",
            idle_hours=100.0,
            avg_cpu=None,
            resource_id="vol-short",
        )
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.LOW


# ===================================================================
# Risk Scoring
# ===================================================================
class TestRiskScoring:
    """Test risk computation logic."""

    def test_dev_with_owner_low_risk(self):
        finding = _make_finding(env="dev", owner="alice@pixelforge.io")
        assert compute_risk(finding) == Risk.LOW

    def test_qa_with_owner_low_risk(self):
        finding = _make_finding(env="qa", owner="bob@pixelforge.io")
        assert compute_risk(finding) == Risk.LOW

    def test_prod_high_risk(self):
        finding = _make_finding(env="prod")
        assert compute_risk(finding) == Risk.HIGH

    def test_keep_true_high_risk(self):
        finding = _make_finding(keep="true")
        assert compute_risk(finding) == Risk.HIGH

    def test_missing_owner_high_risk(self):
        finding = _make_finding(owner="")
        assert compute_risk(finding) == Risk.HIGH

    def test_missing_env_high_risk(self):
        finding = _make_finding(env="")
        assert compute_risk(finding) == Risk.HIGH


# ===================================================================
# Company Policy
# ===================================================================
class TestCompanyPolicy:
    """Test per-company policy loading and overrides."""

    def test_pixelforge_policy_loaded(self):
        """PixelForge policy loads correctly from JSON."""
        policy = load_company_policy("pixelforge")
        assert policy["company"] == "pixelforge"
        assert policy["display_name"] == "PixelForge Studios"
        assert "dev" in policy["overrides"]["env_rules"]
        assert policy["overrides"]["env_rules"]["prod"]["always_escalate"] is True

    def test_unknown_company_default(self):
        """Unknown company returns safe defaults."""
        policy = load_company_policy("unknown_corp")
        assert policy["company"] == "unknown_corp"
        assert policy["overrides"]["env_rules"] == {}

    def test_pixelforge_prod_always_escalate(self):
        """PixelForge prod rule overrides AUTO_REMEDIATE to ESCALATE."""
        finding = _make_finding(env="prod", idle_hours=200.0, avg_cpu=1.0)
        result = evaluate(finding, **EVAL_KWARGS)
        # Even though HIGH confidence, prod always escalates
        assert result.decision == Decision.ESCALATE

    def test_pixelforge_dev_allows_auto(self):
        """PixelForge dev rule allows AUTO_REMEDIATE."""
        finding = _make_finding(
            env="dev", idle_hours=200.0, avg_cpu=2.0, owner="alice@pixelforge.io"
        )
        result = evaluate(finding, **EVAL_KWARGS)
        assert result.decision == Decision.AUTO_REMEDIATE


# ===================================================================
# Circuit Breaker
# ===================================================================
class TestCircuitBreaker:
    """Test the circuit breaker mechanism."""

    def test_under_limit_allows(self):
        """Actions under the limit proceed normally."""
        cb = CircuitBreaker(max_actions=5)
        for _ in range(5):
            decision, tripped = cb.check_and_increment(Decision.AUTO_REMEDIATE)
            assert decision == Decision.AUTO_REMEDIATE
            assert tripped is False
        assert cb.count == 5

    def test_at_limit_trips(self):
        """6th AUTO_REMEDIATE triggers the circuit breaker → ESCALATE."""
        cb = CircuitBreaker(max_actions=5)
        # Use up 5 actions
        for _ in range(5):
            cb.check_and_increment(Decision.AUTO_REMEDIATE)

        # 6th should trip
        decision, tripped = cb.check_and_increment(Decision.AUTO_REMEDIATE)
        assert decision == Decision.ESCALATE
        assert tripped is True
        assert cb.tripped is True

    def test_stays_tripped(self):
        """Once tripped, subsequent calls return ESCALATE (tripped=False since
        the trip event already occurred)."""
        cb = CircuitBreaker(max_actions=5)
        for _ in range(5):
            cb.check_and_increment(Decision.AUTO_REMEDIATE)

        # First trip
        _, tripped1 = cb.check_and_increment(Decision.AUTO_REMEDIATE)
        assert tripped1 is True

        # Second call after trip — still ESCALATE but tripped=False
        decision, tripped2 = cb.check_and_increment(Decision.AUTO_REMEDIATE)
        assert decision == Decision.ESCALATE
        assert tripped2 is False

    def test_non_remediate_not_counted(self):
        """ESCALATE and LOG_ONLY decisions don't count toward the limit."""
        cb = CircuitBreaker(max_actions=5)
        for _ in range(10):
            cb.check_and_increment(Decision.ESCALATE)
            cb.check_and_increment(Decision.LOG_ONLY)
        assert cb.count == 0
        assert cb.tripped is False

    def test_custom_limit(self):
        """Circuit breaker respects custom max_actions."""
        cb = CircuitBreaker(max_actions=2)
        cb.check_and_increment(Decision.AUTO_REMEDIATE)
        cb.check_and_increment(Decision.AUTO_REMEDIATE)
        decision, tripped = cb.check_and_increment(Decision.AUTO_REMEDIATE)
        assert decision == Decision.ESCALATE
        assert tripped is True


# ===================================================================
# Decision Table Direct Tests
# ===================================================================
class TestDecisionTableDirect:
    """Directly test the decision table lookup function."""

    def test_all_combinations(self):
        """Verify all four entries in the decision table."""
        assert apply_decision_table(Confidence.HIGH, Risk.LOW) == Decision.AUTO_REMEDIATE
        assert apply_decision_table(Confidence.HIGH, Risk.HIGH) == Decision.ESCALATE
        assert apply_decision_table(Confidence.LOW, Risk.LOW) == Decision.ESCALATE
        assert apply_decision_table(Confidence.LOW, Risk.HIGH) == Decision.LOG_ONLY


# ===================================================================
# Edge Cases
# ===================================================================
class TestEdgeCases:
    """Test boundary and edge cases."""

    def test_exactly_at_cpu_threshold(self):
        """CPU exactly at threshold (5.0) → NOT idle (LOW confidence)."""
        finding = _make_finding(idle_hours=200.0, avg_cpu=5.0)
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.LOW

    def test_exactly_at_idle_threshold(self):
        """Idle duration exactly at threshold → HIGH confidence."""
        finding = _make_finding(idle_hours=168.0, avg_cpu=2.0)
        conf = compute_confidence(finding, 168.0, 5.0, 720.0)
        assert conf == Confidence.HIGH

    def test_evaluation_result_has_all_fields(self):
        """EvaluationResult contains all required fields."""
        finding = _make_finding()
        result = evaluate(finding, **EVAL_KWARGS)
        assert isinstance(result.finding, Finding)
        assert isinstance(result.confidence, Confidence)
        assert isinstance(result.risk, Risk)
        assert isinstance(result.decision, Decision)
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0
