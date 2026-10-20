#!/usr/bin/env python3
"""
End-to-End Simulation Runner for PixelForge Studios FinOps Auto-Remediation.

Simulates the entire closed-loop lifecycle in an offline mock environment
against the canonical 8-resource specification:
    1. Infrastructure setup (KMS key, DynamoDB composite table, SNS topic, SSM parameter)
    2. Seed canonical 8 resources (idle dev, idle qa, idle qa keep=true, idle prod, busy prod,
       orphan dev EBS, orphan prod EBS, attached prod EBS)
    3. Trigger Scanner Lambda (detects waste and scores findings)
    4. Auto-remediate safe resources (dev-api-01, qa-runner-01 stopped; vol-dev-orphan deleted)
    5. Escalate risky resources (prod-report-01, vol-prod-orphan sent via SNS with HMAC approval)
    6. Ensure protected/active resources remain untouched (qa-loadtest-02 LOG_ONLY, prod-api-01 untouched,
       vol-prod-data untouched)
    7. Simulate manager approval of escalated production resource
    8. Generate and verify decrypted FinOps Audit Report
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Force UTF-8 on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import boto3
from moto import mock_aws

from demo.demo_scenario import CANONICAL_SPEC, seed_canonical_scenario
from src.approval.handler import handler as approval_handler
from src.audit.writer import read_audit_log, write_audit_log
from src.config import Config
from src.escalation.handler import send_escalation_notification
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk, evaluate
from src.remediation.handler import remediate_resource
from src.scanner import ebs_scanner, ec2_scanner

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("finops-demo")


@mock_aws
def run_full_simulation():
    print("=" * 80)
    print("      CLOSED-LOOP FINOPS AUTO-REMEDIATION — CANONICAL DEMO SIMULATION      ")
    print("                         Tenant: PixelForge Studios                         ")
    print("=" * 80)

    region = "ap-south-1"
    os.environ["AWS_DEFAULT_REGION"] = region
    os.environ["DRY_RUN"] = "false"
    os.environ["DEMO_MODE"] = "true"
    os.environ["DEMO_EC2_IDLE_MINUTES"] = "60"
    os.environ["DEMO_EBS_UNATTACHED_MINUTES"] = "120"
    os.environ["AUDIT_TABLE_NAME"] = "finops-audit-log"
    os.environ["HMAC_PARAM_NAME"] = "/finops/hmac-secret"

    # -------------------------------------------------------------------------
    # STEP 1: Set up Cloud Infrastructure (KMS, DynamoDB, SNS, SSM)
    # -------------------------------------------------------------------------
    print("\n[STEP 1] Initializing Cloud Infrastructure...")
    kms = boto3.client("kms", region_name=region)
    ddb = boto3.client("dynamodb", region_name=region)
    sns = boto3.client("sns", region_name=region)
    ssm = boto3.client("ssm", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    cw = boto3.client("cloudwatch", region_name=region)

    key_resp = kms.create_key(Description="FinOps Audit Key")
    key_id = key_resp["KeyMetadata"]["KeyId"]
    os.environ["KMS_KEY_ARN"] = key_id
    kms.create_alias(AliasName="alias/finops-key", TargetKeyId=key_id)
    print(f"  [OK] KMS Key created: {key_id} (Alias: alias/finops-key)")

    ddb.create_table(
        TableName="finops-audit-log",
        KeySchema=[
            {"AttributeName": "tenant_id", "KeyType": "HASH"},
            {"AttributeName": "log_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "tenant_id", "AttributeType": "S"},
            {"AttributeName": "log_id", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    print("  [OK] DynamoDB Table created: finops-audit-log (tenant_id HASH, log_id RANGE)")

    topic_resp = sns.create_topic(Name="finops-escalation-topic")
    topic_arn = topic_resp["TopicArn"]
    os.environ["SNS_TOPIC_ARN"] = topic_arn
    print(f"  [OK] SNS Topic created: {topic_arn}")

    ssm.put_parameter(
        Name="/finops/hmac-secret",
        Value="pixelforge-production-hmac-signing-key-2026",
        Type="String",
    )
    print("  [OK] SSM Parameter created: /finops/hmac-secret")

    # -------------------------------------------------------------------------
    # STEP 2: Seed Canonical 8-Resource Scenario
    # -------------------------------------------------------------------------
    print("\n[STEP 2] Seeding Canonical 8-Resource Scenario...")
    seed_res = seed_canonical_scenario(region=region, is_mock=True)
    inst_map = seed_res["instances"]
    vol_map = seed_res["volumes"]

    assert len(inst_map) == 5, f"Expected 5 instances, got {len(inst_map)}"
    assert len(vol_map) == 3, f"Expected 3 volumes, got {len(vol_map)}"
    print(f"  [OK] Successfully seeded 5 EC2 instances: {list(inst_map.keys())}")
    print(f"  [OK] Successfully seeded 3 EBS volumes: {list(vol_map.keys())}")

    # -------------------------------------------------------------------------
    # STEP 3: Scanner Execution
    # -------------------------------------------------------------------------
    print("\n[STEP 3] Running Scanners (EC2 + EBS)...")
    config = Config()
    ec2_findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)
    ebs_findings = ebs_scanner.scan(config=config, ec2_client=ec2)
    all_findings = ec2_findings + ebs_findings

    detected_resource_names = {f.tags.get("Name"): f for f in all_findings}
    print(f"  [OK] Scanners identified {len(all_findings)} waste candidates:")
    for name, f in detected_resource_names.items():
        print(f"    - {name} ({f.resource_id}, {f.resource_type}): ${f.estimated_monthly_cost:.2f}/mo")

    # Assert false-positive controls: prod-api-01 and vol-prod-data MUST NOT be detected
    assert "prod-api-01" not in detected_resource_names, "False positive! prod-api-01 is busy and should not be detected."
    assert "vol-prod-data" not in detected_resource_names, "False positive! vol-prod-data is attached and should not be detected."
    print("  [OK] False-positive controls verified: prod-api-01 and vol-prod-data untouched.")

    # -------------------------------------------------------------------------
    # STEP 4: Policy Evaluation & Decision Engine
    # -------------------------------------------------------------------------
    print("\n[STEP 4] Evaluating Findings via Decision Table Matrix...")
    decisions_by_name = {}
    eval_results = []
    for f in all_findings:
        ev = evaluate(f, ec2_idle_window_hours=1.0, ebs_unattached_hours=2.0)
        eval_results.append(ev)
        name = f.tags.get("Name", "unnamed")
        decisions_by_name[name] = ev
        print(f"    - {name} ({f.resource_id}): Conf={ev.confidence.value}, Risk={ev.risk.value} -> {ev.decision.value} ({ev.reason})")

    # Validate decisions against canonical specification
    expected_decisions = {
        "dev-api-01": Decision.AUTO_REMEDIATE,
        "qa-runner-01": Decision.AUTO_REMEDIATE,
        "qa-loadtest-02": Decision.LOG_ONLY,
        "prod-report-01": Decision.ESCALATE,
        "vol-dev-orphan": Decision.AUTO_REMEDIATE,
        "vol-prod-orphan": Decision.ESCALATE,
    }

    for name, exp_dec in expected_decisions.items():
        actual = decisions_by_name.get(name)
        assert actual is not None, f"Resource {name} was not evaluated!"
        assert actual.decision == exp_dec, (
            f"Policy mismatch for {name}: expected {exp_dec.value}, got {actual.decision.value}"
        )
    print("  [OK] All policy decisions match the canonical specification perfectly!")

    # -------------------------------------------------------------------------
    # STEP 5: Auto-Remediation Execution
    # -------------------------------------------------------------------------
    print("\n[STEP 5] Executing Auto-Remediation on Safe Findings...")
    auto_remediated = []
    for ev in eval_results:
        f = ev.finding
        name = f.tags.get("Name")
        if ev.decision == Decision.AUTO_REMEDIATE:
            rem_out = remediate_resource(f, config=config, ec2_client=ec2)
            auto_remediated.append(f)
            print(f"  [OK] Auto-remediated {name}: {rem_out['action_detail']}")
            write_audit_log(f, ev, "AUTO_REMEDIATED", config=config, dynamodb_client=ddb, kms_client=kms)
        elif ev.decision == Decision.LOG_ONLY:
            write_audit_log(f, ev, "LOG_ONLY", config=config, dynamodb_client=ddb, kms_client=kms)
            print(f"  [OK] Log-only entry written for {name} ({ev.reason})")

    # Verify states
    dev_desc = ec2.describe_instances(InstanceIds=[inst_map["dev-api-01"]])
    assert dev_desc["Reservations"][0]["Instances"][0]["State"]["Name"] in ["stopping", "stopped"]
    qa_desc = ec2.describe_instances(InstanceIds=[inst_map["qa-runner-01"]])
    assert qa_desc["Reservations"][0]["Instances"][0]["State"]["Name"] in ["stopping", "stopped"]
    qa_keep_desc = ec2.describe_instances(InstanceIds=[inst_map["qa-loadtest-02"]])
    assert qa_keep_desc["Reservations"][0]["Instances"][0]["State"]["Name"] == "running", "qa-loadtest-02 should NOT be stopped!"

    # Verify vol-dev-orphan deleted
    try:
        dev_vols = ec2.describe_volumes(VolumeIds=[vol_map["vol-dev-orphan"]])["Volumes"]
        assert len(dev_vols) == 0 or dev_vols[0].get("State") == "deleted"
    except Exception as e:
        assert "InvalidVolume.NotFound" in str(e) or "does not exist" in str(e)
    print("  [OK] Confirmed dev-api-01 and qa-runner-01 stopped, vol-dev-orphan deleted, qa-loadtest-02 running.")

    # -------------------------------------------------------------------------
    # STEP 6: Escalation via SNS + HMAC Signed URLs
    # -------------------------------------------------------------------------
    print("\n[STEP 6] Escalating Risky Production Resources via SNS...")
    escalations = []
    for ev in eval_results:
        if ev.decision == Decision.ESCALATE:
            f = ev.finding
            name = f.tags.get("Name")
            esc = send_escalation_notification(f, ev, config=config, sns_client=sns, ssm_client=ssm)
            escalations.append((name, f, esc))
            write_audit_log(f, ev, "ESCALATED", config=config, dynamodb_client=ddb, kms_client=kms)
            print(f"  [OK] Escalation notification sent for {name}: {esc['approval_url']}")

    assert len(escalations) == 2, f"Expected 2 escalations, got {len(escalations)}"
    print("  [OK] Escalations completed for prod-report-01 and vol-prod-orphan.")

    # -------------------------------------------------------------------------
    # STEP 7: Manager Approval Simulation
    # -------------------------------------------------------------------------
    print("\n[STEP 7] Simulating Approved Remediation on prod-report-01...")
    prod_report_esc = [e for e in escalations if e[0] == "prod-report-01"][0]
    approval_url = prod_report_esc[2]["approval_url"]
    parsed = urlparse(approval_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    # Two-step approval flow: GET displays confirmation form, POST executes remediation
    get_event = {"httpMethod": "GET", "queryStringParameters": params}
    get_resp = approval_handler(get_event)
    assert get_resp["statusCode"] == 200, f"GET approval failed: {get_resp}"
    assert "Confirm Remediation Approval" in get_resp["body"]

    post_event = {"httpMethod": "POST", "queryStringParameters": params}
    post_resp = approval_handler(post_event)
    assert post_resp["statusCode"] == 200, f"POST approval failed: {post_resp}"
    print(f"  [OK] Approval API executed with status 200 for {params['resource_id']}")

    # Verify prod-report-01 is now stopped
    prod_rep_desc = ec2.describe_instances(InstanceIds=[inst_map["prod-report-01"]])
    assert prod_rep_desc["Reservations"][0]["Instances"][0]["State"]["Name"] in ["stopping", "stopped"]
    print("  [OK] prod-report-01 state verified: STOPPED post-approval.")

    # -------------------------------------------------------------------------
    # STEP 8: Decrypted Audit Trail Verification
    # -------------------------------------------------------------------------
    print("\n[STEP 8] Verifying Encrypted DynamoDB Audit Trail...")
    from scripts.report import generate_report
    generate_report(config=config, ddb_client=ddb, kms_client=kms)

    print("\n" + "=" * 80)
    print("      ALL CANONICAL ASSERTIONS PASSED! DEMO READY FOR ACADEMIC REVIEW       ")
    print("=" * 80)


if __name__ == "__main__":
    run_full_simulation()
