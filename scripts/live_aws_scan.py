#!/usr/bin/env python3
"""
Live AWS Account Scanner & Remediator.

Direct command-line tool for scanning any real AWS account and stopping unused instances.

Usage:
    python scripts/live_aws_scan.py [--region REGION] [--dry-run] [--scope-all]

Examples:
    # Safe Dry Run (Preview only):
    python scripts/live_aws_scan.py --region ap-south-1 --dry-run

    # Live Mode (Stops real idle EC2 instances upon confirmation):
    python scripts/live_aws_scan.py --region ap-south-1 --scope-all
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Force UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import boto3

from src.config import Config
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk, evaluate
from src.remediation.handler import remediate_resource
from src.scanner import ebs_scanner, ec2_scanner

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live-aws-scan")


def main():
    parser = argparse.ArgumentParser(description="Live AWS FinOps Account Scanner")
    parser.add_argument("--region", default="ap-south-1", help="AWS Region (default: ap-south-1)")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Dry run mode (do not stop instances)")
    parser.add_argument("--scope-all", action="store_true", default=False, help="Scan all running instances without requiring Project=finops-demo tag")
    args = parser.parse_args()

    print("=" * 75)
    print("        SCOPEFORGE FINOPS — LIVE REAL AWS ACCOUNT SCANNER & REMEDIATOR        ")
    print("=" * 75)
    print(f"Target Region:    {args.region}")
    print(f"Dry Run Mode:     {args.dry_run}")
    print(f"Scope:            {'ALL instances in region' if args.scope_all else 'Only tagged Project=finops-demo'}")
    print("-" * 75)

    # 1. Verify AWS Identity
    try:
        sts = boto3.client("sts", region_name=args.region)
        identity = sts.get_caller_identity()
        print(f"[OK] Connected to AWS Account ID: {identity['Account']}")
        print(f"[OK] Active IAM Caller ARN:       {identity['Arn']}")
    except Exception as e:
        print(f"\n[ERROR] Could not authenticate with AWS: {e}")
        print("Please configure credentials via 'aws configure' or set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY.")
        sys.exit(1)

    # 2. Configure environment
    os.environ["AWS_DEFAULT_REGION"] = args.region
    os.environ["DRY_RUN"] = "true" if args.dry_run else "false"
    if args.scope_all:
        os.environ["SCOPE_TAG_KEY"] = ""
        os.environ["SCOPE_TAG_VALUE"] = ""
    else:
        os.environ["SCOPE_TAG_KEY"] = "Project"
        os.environ["SCOPE_TAG_VALUE"] = "finops-demo"

    config = Config()
    ec2 = boto3.client("ec2", region_name=args.region)
    cw = boto3.client("cloudwatch", region_name=args.region)

    # 3. Execute Scans
    print("\nScanning EC2 instances for low CPU utilization (< 5.0%)...")
    ec2_findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)

    print("Scanning EBS volumes for unattached ('available') state...")
    ebs_findings = ebs_scanner.scan(config=config, ec2_client=ec2)

    all_findings = ec2_findings + ebs_findings

    if not all_findings:
        print("\n[OK] No waste resources detected in this region. Account is clean!")
        print("=" * 75)
        return

    print(f"\nDetected {len(all_findings)} waste resources:")
    print("-" * 75)
    print(f"{'Type':<6} {'Resource ID':<22} {'Env':<6} {'Avg CPU':<9} {'Idle':<9} {'Est. Cost/Mo':<12}")
    print("-" * 75)

    auto_rem_findings = []
    escalate_findings = []

    for f in all_findings:
        cpu_str = f"{f.avg_cpu:.1f}%" if f.avg_cpu is not None else "N/A"
        env = f.tags.get("env", "unknown")
        print(f"{f.resource_type.upper():<6} {f.resource_id:<22} {env:<6} {cpu_str:<9} {f.idle_duration_hours:<9.1f} ${f.estimated_monthly_cost:<11.2f}")

        ev = evaluate(
            f,
            ec2_idle_window_hours=1.0 if config.demo_mode else 168.0,
            ebs_unattached_hours=2.0 if config.demo_mode else 720.0,
            scope_tag_key="" if args.scope_all else "Project",
            scope_tag_value="" if args.scope_all else "finops-demo",
        )
        if ev.decision == Decision.AUTO_REMEDIATE:
            auto_rem_findings.append(f)
        else:
            escalate_findings.append((f, ev))

    total_waste = sum(f.estimated_monthly_cost for f in all_findings)
    print("-" * 75)
    print(f"Total Estimated Waste: ${total_waste:.2f}/month (${total_waste * 12:.2f}/year)")
    print(f"Safe to auto-remediate: {len(auto_rem_findings)} | Risky / Escalations: {len(escalate_findings)}")

    # 4. Remediation Prompt
    if auto_rem_findings and not args.dry_run:
        print(f"\n[ATTENTION] Ready to stop {len(auto_rem_findings)} idle instances on real AWS account {identity['Account']}.")
        confirm = input("Proceed with stopping these instances? (yes/no): ").strip().lower()
        if confirm == "yes":
            for f in auto_rem_findings:
                res = remediate_resource(f, config=config, ec2_client=ec2)
                print(f"[SUCCESS] {res['action_detail']}")
        else:
            print("[INFO] Remediation skipped by user.")
    elif args.dry_run:
        print("\n[DRY RUN ACTIVE] No instances were modified. Rerun without --dry-run to stop idle instances.")

    print("\n" + "=" * 75)


if __name__ == "__main__":
    main()
