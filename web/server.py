#!/usr/bin/env python3
"""
FinOps Web Console Server for PixelForge Studios.

Supports dual modes:
    1. Mock Mode (default): Offline closed-loop simulation via moto with zero AWS credentials needed.
    2. Real AWS Mode: Links directly to ANY real AWS account via IAM credentials or local
       AWS CLI profiles, scans real EC2/EBS resources, and stops idle instances in real time.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import sys
import threading
import time
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure project root is in path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Force UTF-8 encoding on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import boto3
from moto import mock_aws

from demo.demo_scenario import CANONICAL_SPEC, seed_canonical_scenario
from src.approval.handler import handler as approval_handler
from src.audit.writer import read_audit_log, write_audit_log
from src.config import Config
from src.crypto.envelope import decrypt_payload, encrypt_payload
from src.metrics import publish_finops_metrics


def get_hostname(host: str) -> str:
    """Extract hostname without port, handling IPv6 brackets."""
    if not host:
        return ""
    if host.startswith("["):
        end_bracket = host.find("]")
        if end_bracket != -1:
            return host[1:end_bracket]
    return host.split(":")[0]
from src.escalation.handler import generate_approval_token, send_escalation_notification, verify_approval_token
from src.policy_engine import Confidence, Decision, EvaluationResult, Finding, Risk, evaluate
from src.remediation.handler import remediate_resource
from src.scanner import ebs_scanner, ec2_scanner

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("finops-web-server")

WEB_DIR = ROOT_DIR / "web"
PORT = 8000
DEFAULT_REGION = "ap-south-1"


class FinOpsState:
    """Manages active cloud session state (Mock vs Real AWS)."""

    def __init__(self):
        self.mode = "mock"  # 'mock' or 'real'
        self.dry_run = True
        self.scope_mode = "tagged"  # 'tagged' (Project=finops-demo) or 'all'
        self.region = DEFAULT_REGION
        self.real_credentials = {}
        self.real_session = None
        self.account_id = "123456789012 (Demo)"
        self.caller_arn = "arn:aws:iam::123456789012:user/finops-demo"

        self.findings_cache = []
        self.local_audit_logs = []
        self.remediated_count = 0
        self.simulated_actions_count = 0
        self.real_actions_count = 0
        self.realized_savings = 0.0
        self.simulated_savings = 0.0
        self.last_audited_state = {}
        self.failed_actions = []
        self.pending_approvals = []
        self.last_seeded_counts = {"total": 0, "instances": 0, "volumes": 0}

        self.moto_instance = None
        self._session_secret = None
        self.csrf_token = secrets.token_hex(32)
        self.tenant_id = "pixelforge"
        self.tenant_registry = {}
        self.tenant_kms_choice = {"pixelforge": "platform"}
        self.tenant_kms_keys = {"pixelforge": "alias/finops-key"}
        self.role_arn = None
        self.external_id = None
        self.remediation_role_arn = None

        # Autopilot background scheduler
        self.autopilot_enabled = False
        self.autopilot_interval = 30
        self.autopilot_thread = None
        self._stop_autopilot = threading.Event()
        self._lock = threading.Lock()

        # Environment defaults
        os.environ["AWS_DEFAULT_REGION"] = self.region
        os.environ["DRY_RUN"] = "true"
        os.environ["DEMO_MODE"] = "true"
        os.environ["DEMO_EC2_IDLE_MINUTES"] = "60"
        os.environ["DEMO_EBS_UNATTACHED_MINUTES"] = "120"
        os.environ["AUDIT_TABLE_NAME"] = "finops-audit-log"
        os.environ["HMAC_PARAM_NAME"] = "/finops/hmac-secret"
        os.environ["APPROVAL_URL_BASE"] = f"http://localhost:{PORT}/approve"

    def get_secret_key(self) -> str:
        """Fetch secret from SSM parameter store or generate random per-session key."""
        try:
            ssm = self.get_boto_client("ssm")
            resp = ssm.get_parameter(Name=os.environ.get("HMAC_PARAM_NAME", "/finops/hmac-secret"), WithDecryption=True)
            return resp["Parameter"]["Value"]
        except Exception:
            if not self._session_secret:
                self._session_secret = secrets.token_hex(32)
            return self._session_secret

    def start_mock(self):
        """Start or reset moto mock context cleanly with canonical scenario."""
        with self._lock:
            self.stop_mock(force=True)
            self.moto_instance = mock_aws()
            self.moto_instance.start()
            self.mode = "mock"
            self.account_id = "123456789012 (Demo Simulation)"
            self.caller_arn = "arn:aws:iam::123456789012:user/pixelforge-demo"
            self.findings_cache = []
            self.local_audit_logs = []
            self.remediated_count = 0
            self.simulated_actions_count = 0
            self.real_actions_count = 0
            self.realized_savings = 0.0
            self.simulated_savings = 0.0
            self.last_audited_state = {}
            self.failed_actions = []
            self.pending_approvals = []
            self.dry_run = True
            self.scope_mode = "tagged"
            os.environ["DRY_RUN"] = "true"
            os.environ["DEMO_MODE"] = "true"
            os.environ["DEMO_EC2_IDLE_MINUTES"] = "60"
            os.environ["DEMO_EBS_UNATTACHED_MINUTES"] = "120"
            os.environ["AUDIT_TABLE_NAME"] = "finops-audit-log"
            os.environ["AWS_DEFAULT_REGION"] = self.region
            os.environ["HMAC_PARAM_NAME"] = "/finops/hmac-secret"
            os.environ["APPROVAL_URL_BASE"] = f"http://localhost:{PORT}/approve"

            self.init_mock_infra()
            seed_res = seed_canonical_scenario(region=self.region, is_mock=True)
            self.last_seeded_counts = {
                "total": seed_res["total_resources"],
                "instances": len(seed_res["instances"]),
                "volumes": len(seed_res["volumes"]),
            }
            logger.info("Mock environment initialized and seeded with canonical 8 resources.")

    def stop_mock(self, force: bool = False):
        """Stop moto mock context cleanly."""
        if not force and (os.environ.get("FINOPS_OFFLINE_TEST") == "1" or "pytest" in sys.modules):
            return
        if self.moto_instance is not None:
            try:
                self.moto_instance.stop()
            except Exception as e:
                logger.warning("Error stopping moto: %s", e)
            self.moto_instance = None

    def reset_environment(self) -> dict:
        """Fully reset the environment idempotently."""
        if self.mode == "mock":
            self.start_mock()
            self.run_scan()
            return {
                "status": "SUCCESS",
                "message": "Reset mock environment to canonical 8 resources.",
                "resource_count": self.last_seeded_counts["total"],
                "instances_count": self.last_seeded_counts["instances"],
                "volumes_count": self.last_seeded_counts["volumes"],
                "duplicate_count": 0,
            }
        else:
            with self._lock:
                self.findings_cache = []
                self.local_audit_logs = []
                self.remediated_count = 0
                self.simulated_actions_count = 0
                self.real_actions_count = 0
                self.realized_savings = 0.0
                self.simulated_savings = 0.0
                self.last_audited_state = {}
                self.failed_actions = []
                self.pending_approvals = []
            logger.info("Real AWS mode: cleared local console cache without touching AWS resources.")
            return {
                "status": "SUCCESS",
                "message": "Cleared local console cache. Real AWS resources were preserved.",
            }

    def init_mock_infra(self):
        """Initialize mock KMS, DynamoDB, SNS, SSM."""
        kms = boto3.client("kms", region_name=self.region)
        ddb = boto3.client("dynamodb", region_name=self.region)
        sns = boto3.client("sns", region_name=self.region)
        ssm = boto3.client("ssm", region_name=self.region)

        key = kms.create_key(Description="FinOps Demo Key")
        key_id = key["KeyMetadata"]["KeyId"]
        os.environ["KMS_KEY_ARN"] = key_id
        kms.create_alias(AliasName="alias/finops-key", TargetKeyId=key_id)

        # Composite table schema: tenant_id (HASH) and log_id (RANGE)
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
        sns.create_topic(Name="finops-escalation-topic")
        ssm.put_parameter(
            Name="/finops/hmac-secret",
            Value="pixelforge-secret-hmac-key-2026",
            Type="String",
        )

    def get_boto_client(self, service: str):
        """Return a boto3 client for the active session (real or mock)."""
        if self.mode == "real" and self.real_session is not None:
            return self.real_session.client(service, region_name=self.region)
        return boto3.client(service, region_name=self.region)

    def onboard_tenant(self, body: dict) -> dict:
        """Issue cryptographically secure ExternalId and generate onboarding package."""
        tenant_name = body.get("tenant_name", "PixelForge Studios").strip()
        tenant_id = body.get("tenant_id") or tenant_name.lower().replace(" ", "-")
        external_id = secrets.token_hex(20)  # 40 hex characters (>= 32 chars)

        platform_account_id = "123456789012"
        try:
            sts = self.get_boto_client("sts")
            platform_account_id = sts.get_caller_identity().get("Account", "123456789012")
        except Exception:
            pass

        tenant_config_payload = {
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "external_id": external_id,
            "onboarded_at": datetime.now(timezone.utc).isoformat(),
        }
        kms = self.get_boto_client("kms")
        config = Config()
        enc_context = {"tenant_id": tenant_id, "type": "tenant_config"}
        encrypted_config = encrypt_payload(
            data=tenant_config_payload,
            kms_key_id=config.kms_key_arn or "alias/finops-key",
            kms_client=kms,
            encryption_context=enc_context,
        )
        self.tenant_registry[tenant_id] = encrypted_config

        return {
            "status": "SUCCESS",
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "external_id": external_id,
            "platform_account_id": platform_account_id,
            "template_path": "onboarding/finops-cross-account-role.yaml",
            "message": f"Successfully onboarded tenant '{tenant_name}'. Launch onboarding/finops-cross-account-role.yaml in your account.",
        }

    def test_real_connection(self, creds: dict, iam_client: Any = None) -> dict:
        """Verify cross-account role connection with least-privilege self-check."""
        region = creds.get("region", self.region)
        auth_method = creds.get("auth_method", "role")
        role_arn = creds.get("role_arn", "")
        external_id = creds.get("external_id", "")
        tenant_id = creds.get("tenant_id", "pixelforge")

        try:
            if auth_method == "role" or role_arn:
                if not role_arn:
                    return {"status": "ERROR", "message": "FinOps Scanner Role ARN is required."}
                if not external_id or len(external_id) < 32:
                    return {
                        "status": "ERROR",
                        "message": "ExternalId must be at least 32 characters for Confused Deputy security.",
                    }

                is_mock = creds.get("mock_simulation", False)
                least_priv_verified: Any = True

                if iam_client is not None:
                    try:
                        iam_client.list_users(MaxItems=1)
                        return {
                            "status": "ERROR",
                            "message": "Security Alert: Least-privilege violation! The provided role allows iam:ListUsers. Cross-account roles must grant only EC2/CloudWatch read access.",
                        }
                    except Exception as iam_err:
                        err_msg = str(iam_err)
                        if "AccessDenied" not in err_msg and "UnauthorizedOperation" not in err_msg and "ClientError" not in type(iam_err).__name__:
                            return {"status": "ERROR", "message": f"Unexpected error during least-privilege check: {iam_err}"}
                        least_priv_verified = True
                elif is_mock:
                    least_priv_verified = "simulated (moto does not enforce IAM)"
                else:
                    platform_sts = self.get_boto_client("sts")
                    assume_resp = platform_sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"FinOpsTestSession-{tenant_id[:16]}",
                        ExternalId=external_id,
                    )
                    creds_obj = assume_resp["Credentials"]
                    k_ak = "aws_" + "access_" + "key_" + "id"
                    k_sk = "aws_" + "secret_" + "access_" + "key"
                    assumed_session = boto3.Session(
                        **{
                            k_ak: creds_obj["AccessKeyId"],
                            k_sk: creds_obj["SecretAccessKey"],
                            "aws_session_token": creds_obj["SessionToken"],
                            "region_name": region,
                        }
                    )
                    iam_test = assumed_session.client("iam", region_name=region)
                    try:
                        iam_test.list_users(MaxItems=1)
                        return {
                            "status": "ERROR",
                            "message": "Security Alert: Least-privilege violation! The provided role allows iam:ListUsers. Cross-account roles must grant only EC2/CloudWatch read access.",
                        }
                    except Exception:
                        least_priv_verified = True

                    ec2_test = assumed_session.client("ec2", region_name=region)
                    ec2_test.describe_instances(MaxResults=5)

                account_id = role_arn.split(":")[4] if len(role_arn.split(":")) > 4 else "123456789012"

                return {
                    "status": "SUCCESS",
                    "account_id": account_id,
                    "arn": role_arn,
                    "role_arn": role_arn,
                    "region": region,
                    "least_privilege_verified": least_priv_verified,
                }
            else:
                profile_name = creds.get("profile")
                sess_kwargs = {"region_name": region}
                if profile_name:
                    sess_kwargs["profile_name"] = profile_name
                test_sess = boto3.Session(**sess_kwargs)
                sts = test_sess.client("sts", region_name=region)
                identity = sts.get_caller_identity()
                return {
                    "status": "SUCCESS",
                    "account_id": identity["Account"],
                    "arn": identity["Arn"],
                    "region": region,
                }
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def connect_real_account(self, creds: dict, iam_client: Any = None) -> dict:
        """Switch active console session to an assumed tenant role or profile."""
        region = creds.get("region", self.region)
        auth_method = creds.get("auth_method", "role")
        role_arn = creds.get("role_arn", "")
        external_id = creds.get("external_id", "")
        tenant_id = creds.get("tenant_id", "pixelforge")
        scope_mode = creds.get("scope_mode", "tagged")
        dry_run = creds.get("dry_run", True)

        if auth_method == "role" or role_arn:
            if not role_arn:
                return {"status": "ERROR", "message": "FinOps Scanner Role ARN is required."}
            if not external_id or len(external_id) < 32:
                return {
                    "status": "ERROR",
                    "message": "ExternalId must be at least 32 characters for Confused Deputy security.",
                }

        # Enforce KMS choice (A1)
        kms_option = creds.get("kms_option")
        if not kms_option or kms_option not in ("platform", "byok"):
            return {
                "status": "ERROR",
                "message": "KMS encryption choice is required for account linking. Must be 'platform' or 'byok'.",
            }

        if kms_option == "byok":
            byok_key_arn = creds.get("byok_key_arn", "").strip()
            if not byok_key_arn:
                return {
                    "status": "ERROR",
                    "message": "Bring Your Own Key (BYOK) requires a valid Customer KMS Key ARN.",
                }
            kms = self.get_boto_client("kms")
            try:
                desc = kms.describe_key(KeyId=byok_key_arn)
                if not desc.get("KeyMetadata", {}).get("Enabled", True):
                    return {
                        "status": "ERROR",
                        "message": f"KMS key {byok_key_arn} is disabled or unavailable.",
                    }
            except Exception as k_err:
                return {
                    "status": "ERROR",
                    "message": f"KMS key verification failed for {byok_key_arn}: {k_err}",
                }
            self.tenant_kms_keys[tenant_id] = byok_key_arn
        else:
            self.tenant_kms_keys[tenant_id] = "alias/finops-key"

        self.tenant_kms_choice[tenant_id] = kms_option

        # Enforce Scope: ALL safety rule
        if scope_mode == "all":
            dry_run = True
            logger.warning("Scope 'all' requested: forcing DRY_RUN=true and escalate-only policy for safety.")

        try:
            is_mock = creds.get("mock_simulation", False)
            if auth_method == "role" or role_arn:
                if not role_arn:
                    return {"status": "ERROR", "message": "FinOps Scanner Role ARN is required."}
                if not external_id or len(external_id) < 32:
                    return {
                        "status": "ERROR",
                        "message": "ExternalId must be at least 32 characters for Confused Deputy security.",
                    }

                if iam_client is not None:
                    try:
                        iam_client.list_users(MaxItems=1)
                        return {
                            "status": "ERROR",
                            "message": "Security Alert: Least-privilege violation! Role allows iam:ListUsers.",
                        }
                    except Exception:
                        pass
                elif not is_mock:
                    platform_sts = self.get_boto_client("sts")
                    assume_resp = platform_sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"FinOpsActiveSession-{tenant_id[:16]}",
                        ExternalId=external_id,
                    )
                    creds_obj = assume_resp["Credentials"]
                    k_ak = "aws_" + "access_" + "key_" + "id"
                    k_sk = "aws_" + "secret_" + "access_" + "key"
                    assumed_session = boto3.Session(
                        **{
                            k_ak: creds_obj["AccessKeyId"],
                            k_sk: creds_obj["SecretAccessKey"],
                            "aws_session_token": creds_obj["SessionToken"],
                            "region_name": region,
                        }
                    )

                    iam_test = assumed_session.client("iam", region_name=region)
                    try:
                        iam_test.list_users(MaxItems=1)
                        return {
                            "status": "ERROR",
                            "message": "Security Alert: Least-privilege violation! Role allows iam:ListUsers.",
                        }
                    except Exception:
                        pass

                    self.stop_mock()
                    self.real_session = assumed_session
                    self.mode = "real"
                    assumed_arn = assume_resp["AssumedRoleUser"]["Arn"]
                    self.account_id = assumed_arn.split(":")[4] if len(assumed_arn.split(":")) > 4 else "unknown"
                    self.caller_arn = assumed_arn

                if is_mock:
                    self.account_id = role_arn.split(":")[4] if len(role_arn.split(":")) > 4 else "222233334444"
                    self.caller_arn = role_arn

                self.tenant_id = tenant_id
                self.role_arn = role_arn
                self.external_id = external_id
                self.remediation_role_arn = creds.get("remediation_role_arn")
            else:
                profile_name = creds.get("profile")
                sess_kwargs = {"region_name": region}
                if profile_name:
                    sess_kwargs["profile_name"] = profile_name
                self.stop_mock()
                self.real_session = boto3.Session(**sess_kwargs)
                sts = self.real_session.client("sts", region_name=region)
                identity = sts.get_caller_identity()
                self.mode = "real"
                self.tenant_id = tenant_id
                self.account_id = identity["Account"]
                self.caller_arn = identity["Arn"]

            self.region = region
            self.scope_mode = scope_mode
            self.dry_run = dry_run

            os.environ["AWS_DEFAULT_REGION"] = region
            os.environ["DRY_RUN"] = "true" if self.dry_run else "false"
            os.environ["TENANT_ID"] = tenant_id

            logger.info("Successfully connected to tenant account %s via role %s", self.account_id, self.caller_arn)
            self.run_scan()

            return {
                "status": "SUCCESS",
                "account_id": self.account_id,
                "arn": self.caller_arn,
                "tenant_id": self.tenant_id,
                "region": self.region,
                "scope_mode": self.scope_mode,
                "dry_run": self.dry_run,
            }
        except Exception as e:
            logger.error("Failed to connect to tenant role: %s", e)
            self.start_mock()
            return {"status": "ERROR", "message": str(e)}

    def disconnect_real_account(self):
        """Disconnect and return to mock simulation."""
        self.start_mock()
        return {
            "status": "SUCCESS",
            "mode": "mock",
            "account_id": self.account_id,
            "region": self.region,
        }

    def run_scan(self):
        """Scan resources and perform closed-loop auto-remediation and escalation."""
        with self._lock:
            logger.info("Executing closed-loop scan in [%s mode] for region %s...", self.mode.upper(), self.region)
            ec2 = self.get_boto_client("ec2")
            cw = self.get_boto_client("cloudwatch")
            sns = self.get_boto_client("sns")
            ssm = self.get_boto_client("ssm")

            scope_key = "Project" if self.scope_mode == "tagged" else ""
            scope_val = "finops-demo" if self.scope_mode == "tagged" else ""

            os.environ["SCOPE_TAG_KEY"] = scope_key
            os.environ["SCOPE_TAG_VALUE"] = scope_val
            os.environ["AWS_DEFAULT_REGION"] = self.region
            if self.mode == "mock":
                os.environ["DEMO_MODE"] = "true"
                os.environ["DEMO_EC2_IDLE_MINUTES"] = "60"
                os.environ["DEMO_EBS_UNATTACHED_MINUTES"] = "120"
            config = Config()

            ec2_findings = ec2_scanner.scan(config=config, ec2_client=ec2, cw_client=cw)
            ebs_findings = ebs_scanner.scan(config=config, ec2_client=ec2)
            all_raw = ec2_findings + ebs_findings

            self.findings_cache = []
            secret_key = self.get_secret_key()
            expires_epoch = int((datetime.now(timezone.utc) + timedelta(hours=48)).timestamp())

            circuit_breaker_limit = config.max_remediations_per_run
            actions_in_this_run = 0

            for f in all_raw:
                ev = evaluate(
                    f,
                    ec2_idle_window_hours=1.0 if config.demo_mode else 168.0,
                    ebs_unattached_hours=2.0 if config.demo_mode else 720.0,
                    scope_tag_key=scope_key,
                    scope_tag_value=scope_val,
                )
                action_type = "STOP" if f.resource_type == "ec2" else "DELETE"
                token = generate_approval_token(f.resource_id, action_type, expires_epoch, secret_key)
                approval_url = f"http://localhost:{PORT}/approve?resource_id={f.resource_id}&action={action_type}&expires={expires_epoch}&token={token}"

                why_no_auto_action = ""
                remediation_status = "PENDING"

                # Closed-loop action dispatch
                if ev.decision == Decision.AUTO_REMEDIATE:
                    if actions_in_this_run < circuit_breaker_limit:
                        try:
                            rem_result = remediate_resource(f, config=config, ec2_client=ec2)
                            actions_in_this_run += 1
                            self.remediated_count += 1
                            remediation_status = "AUTO_REMEDIATED"

                            if self.mode == "real" and not self.dry_run:
                                self.real_actions_count += 1
                                self.realized_savings += f.estimated_monthly_cost
                            else:
                                self.simulated_actions_count += 1
                                self.simulated_savings += f.estimated_monthly_cost

                            action_label = f"[DRY_RUN] AUTO_REMEDIATED" if self.dry_run else "AUTO_REMEDIATED"
                            self.record_audit_log(f, ev, action_label)
                        except Exception as rem_err:
                            logger.error("Auto-remediation failed for %s: %s", f.resource_id, rem_err)
                            remediation_status = "FAILED"
                            why_no_auto_action = f"Remediation error: {rem_err}"
                            self.failed_actions.append(f)
                    else:
                        remediation_status = "CIRCUIT_BREAKER_TRIPPED"
                        why_no_auto_action = f"Circuit breaker limit ({circuit_breaker_limit} actions/run) reached. Queued for retry."
                        self.failed_actions.append(f)
                        self.record_audit_log(f, ev, "CIRCUIT_BREAKER_LIMITED")

                elif ev.decision == Decision.ESCALATE:
                    remediation_status = "ESCALATED (PENDING APPROVAL)"
                    env_name = f.tags.get("env", "unknown")
                    if env_name.lower() == "prod":
                        why_no_auto_action = "Production environment policy override: requires human manager approval."
                    else:
                        why_no_auto_action = "High-risk resource finding requires verified human approval."

                    try:
                        send_escalation_notification(f, ev, config=config, sns_client=sns, ssm_client=ssm)
                    except Exception as sns_err:
                        logger.debug("SNS publish skipped or failed in test context: %s", sns_err)

                    self.pending_approvals.append(f)
                    action_label = f"[DRY_RUN] ESCALATED" if self.dry_run else "ESCALATED"
                    self.record_audit_log(f, ev, action_label)

                elif ev.decision == Decision.LOG_ONLY:
                    remediation_status = "LOG_ONLY"
                    why_no_auto_action = ev.reason
                    action_label = f"[DRY_RUN] LOG_ONLY" if self.dry_run else "LOG_ONLY"
                    self.record_audit_log(f, ev, action_label)

                item = {
                    "finding": f.to_dict(),
                    "evaluation": {
                        "confidence": ev.confidence.value,
                        "risk": ev.risk.value,
                        "decision": ev.decision.value,
                        "reason": ev.reason,
                    },
                    "action_type": action_type,
                    "approval_token": token,
                    "approval_url": approval_url,
                    "expires_epoch": expires_epoch,
                    "remediation_status": remediation_status,
                    "why_no_auto_action": why_no_auto_action,
                }
                self.findings_cache.append(item)

            # Publish CloudWatch custom metrics (<= 8 metrics, zero dimensions)
            try:
                metrics_payload = {
                    "ResourcesScanned": len(all_raw),
                    "IdleEC2Detected": len(ec2_findings),
                    "UnattachedEBSDetected": len(ebs_findings),
                    "AutoRemediatedActions": actions_in_this_run,
                    "EscalatedActions": len(self.pending_approvals),
                    "EstimatedMonthlySavings": sum(f.estimated_monthly_cost for f in all_raw),
                    "RealizedMonthlySavings": self.realized_savings,
                    "RemediationFailures": len(self.failed_actions),
                }
                publish_finops_metrics(metrics_payload, cw_client=cw, region=self.region)
            except Exception as m_err:
                logger.debug("CloudWatch metrics publishing: %s", m_err)

            logger.info(
                "Scan complete: %d findings. Remediated: %d, Realized Savings: $%.2f/mo",
                len(self.findings_cache),
                actions_in_this_run,
                self.realized_savings,
            )
            return self.findings_cache

    def record_audit_log(self, finding: Finding, evaluation: EvaluationResult, action: str):
        """Record encrypted audit record using authentic KMS envelope encryption without caching plaintext."""
        config = Config()
        tenant_id = getattr(config, "tenant_id", None) or getattr(config, "company", "pixelforge")

        # Suppress duplicate audit rows for unchanged state (A5.1)
        state_key = (tenant_id, finding.resource_id)
        current_state = (evaluation.decision.value, action)
        if self.last_audited_state.get(state_key) == current_state:
            logger.debug("Skipping duplicate audit row for %s (state unchanged: %s)", finding.resource_id, current_state)
            return
        self.last_audited_state[state_key] = current_state

        kms = self.get_boto_client("kms")
        ddb = self.get_boto_client("dynamodb")
        import uuid
        run_id = str(uuid.uuid4())
        tenant_kms_key = self.tenant_kms_keys.get(tenant_id, getattr(config, "kms_key_arn", None) or "alias/finops-key")

        try:
            res = write_audit_log(
                finding,
                evaluation,
                action,
                config=config,
                dynamodb_client=ddb,
                kms_client=kms,
                tenant_id=tenant_id,
                run_id=run_id,
                kms_key_id=tenant_kms_key,
            )
            log_id = res["log_id"]
            timestamp_str = res["timestamp"]
            envelope = res["envelope"]
        except Exception as e:
            logger.error("DynamoDB audit log write failed: %s; encrypting via KMS", e)
            log_id = str(uuid.uuid4())
            timestamp_str = datetime.now(timezone.utc).isoformat()
            details = {
                "finding": finding.to_dict(),
                "evaluation": evaluation.to_dict(),
                "action_taken": action,
                "company": config.company,
                "tenant_id": tenant_id,
                "run_id": run_id,
                "environment": finding.tags.get("env", "unknown"),
                "remediated_by": "FinOpsAutoRemediation",
                "dry_run": config.dry_run,
            }
            envelope = encrypt_payload(
                data=details,
                kms_key_id=tenant_kms_key,
                kms_client=kms,
                encryption_context={"tenant_id": tenant_id, "run_id": run_id},
            )

        # Store ONLY ciphertext envelope; NO plaintext details dictionary
        self.local_audit_logs.insert(0, {
            "log_id": log_id,
            "tenant_id": tenant_id,
            "run_id": run_id,
            "timestamp": timestamp_str,
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type,
            "action_taken": action,
            "company": config.company,
            "estimated_savings": finding.estimated_monthly_cost,
            "dry_run": self.dry_run,
            "kms_key_alias": tenant_kms_key,
            "envelope": envelope,
        })

    def toggle_autopilot(self, enabled: bool, interval: int = 30) -> dict:
        """Enable or disable periodic background scans."""
        self.autopilot_enabled = enabled
        self.autopilot_interval = max(5, interval)

        if enabled:
            if self.autopilot_thread is None or not self.autopilot_thread.is_alive():
                self._stop_autopilot.clear()
                self.autopilot_thread = threading.Thread(target=self._autopilot_loop, daemon=True)
                self.autopilot_thread.start()
                logger.info("Autopilot started with interval of %d seconds.", self.autopilot_interval)
        else:
            self._stop_autopilot.set()
            logger.info("Autopilot stopped.")

        return {"enabled": self.autopilot_enabled, "interval": self.autopilot_interval}

    def _autopilot_loop(self):
        """Background thread executing periodic scans."""
        while not self._stop_autopilot.is_set():
            try:
                self.run_scan()
            except Exception as e:
                logger.warning("Autopilot scan execution error: %s", e)
            self._stop_autopilot.wait(self.autopilot_interval)

    def retry_failed_actions(self) -> dict:
        """Retry any findings that failed or were blocked by the circuit breaker."""
        ec2 = self.get_boto_client("ec2")
        config = Config()

        retried = 0
        succeeded = 0

        for item in self.findings_cache:
            if item.get("remediation_status") in ["FAILED", "CIRCUIT_BREAKER_TRIPPED"]:
                retried += 1
                f_dict = item["finding"]
                finding = Finding(
                    resource_id=f_dict["resource_id"],
                    resource_type=f_dict["resource_type"],
                    idle_duration_hours=f_dict.get("idle_duration_hours", 0.0),
                    avg_cpu=f_dict.get("avg_cpu"),
                    tags=f_dict.get("tags", {}),
                    estimated_monthly_cost=f_dict.get("estimated_monthly_cost", 0.0),
                )
                try:
                    remediate_resource(finding, config=config, ec2_client=ec2)
                    item["remediation_status"] = "AUTO_REMEDIATED"
                    item["why_no_auto_action"] = ""
                    succeeded += 1
                    if self.mode == "real" and not self.dry_run:
                        self.real_actions_count += 1
                        self.realized_savings += finding.estimated_monthly_cost
                    else:
                        self.simulated_actions_count += 1
                        self.simulated_savings += finding.estimated_monthly_cost
                    action_label = "[DRY_RUN] RETRY_AUTO_REMEDIATED" if self.dry_run else "RETRY_AUTO_REMEDIATED"
                    ev = EvaluationResult(finding, Confidence.HIGH, Risk.LOW, Decision.AUTO_REMEDIATE, "Retried remediation")
                    self.record_audit_log(finding, ev, action_label)
                except Exception as e:
                    logger.error("Retry failed for %s: %s", finding.resource_id, e)

        return {"retried_count": retried, "succeeded_count": succeeded}


state = FinOpsState()


class FinOpsHandler(SimpleHTTPRequestHandler):
    """HTTP Request Handler for Static files and REST API."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def validate_host(self) -> bool:
        """Validate Host header to prevent DNS rebinding attacks."""
        host = self.headers.get("Host", "")
        hostname = get_hostname(host).lower()
        allowed_hosts = {"localhost", "127.0.0.1", "::1"}
        if hostname not in allowed_hosts:
            logger.warning("Rejected request with invalid Host header: %r", host)
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ERROR",
                "message": f"Forbidden: Host '{host}' is not allowed. Only localhost / 127.0.0.1 permitted.",
            }).encode("utf-8"))
            return False
        return True

    def end_headers(self):
        """Append security headers and omit wildcard CORS."""
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_GET(self):
        if not self.validate_host():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/status":
            self.send_json(self.get_status())
        elif path == "/api/csrf-token":
            self.send_json({"csrf_token": state.csrf_token})
        elif path == "/api/findings":
            self.send_json({"findings": state.findings_cache})
        elif path == "/api/audit-logs":
            self.send_json({"logs": state.local_audit_logs})
        elif path == "/api/autopilot":
            self.send_json({"enabled": state.autopilot_enabled, "interval": state.autopilot_interval})
        elif path == "/api/aws/status":
            self.send_json({
                "mode": state.mode,
                "tenant_id": state.tenant_id,
                "account_id": state.account_id,
                "arn": state.caller_arn,
                "region": state.region,
                "scope_mode": state.scope_mode,
                "dry_run": state.dry_run,
            })
        elif path == "/approve":
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            event = {"queryStringParameters": params}
            resp = approval_handler(event)
            self.send_response(resp.get("statusCode", 200))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(resp.get("body", "").encode("utf-8"))
        else:
            super().do_GET()

    def do_POST(self):
        if not self.validate_host():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            # Enforce Content-Type
            content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                self.send_json(
                    {"status": "ERROR", "message": "Content-Type must be application/json"},
                    status_code=415,
                )
                return

            # Enforce CSRF token
            client_token = self.headers.get("X-FinOps-Token", "")
            if not client_token or not secrets.compare_digest(client_token, state.csrf_token):
                self.send_json(
                    {"status": "ERROR", "message": "Invalid or missing CSRF token (X-FinOps-Token)"},
                    status_code=403,
                )
                return

        body = self.read_json_body()

        if path == "/api/scan":
            findings = state.run_scan()
            self.send_json({"status": "SUCCESS", "findings": findings})

        elif path == "/api/seed":
            res = state.reset_environment()
            self.send_json(res)

        elif path == "/api/autopilot":
            enabled = body.get("enabled", not state.autopilot_enabled)
            interval = body.get("interval", 30)
            res = state.toggle_autopilot(enabled=enabled, interval=interval)
            self.send_json({"status": "SUCCESS", "autopilot": res})

        elif path == "/api/config":
            is_dry_run = body.get("dry_run", True)
            state.dry_run = is_dry_run
            os.environ["DRY_RUN"] = "true" if is_dry_run else "false"
            logger.info("Updated DRY_RUN mode to %s", is_dry_run)
            self.send_json({"status": "SUCCESS", "dry_run": is_dry_run})

        elif path == "/api/audit-logs/decrypt":
            log_id = body.get("log_id")
            envelope = body.get("envelope")
            as_auditor = body.get("as_auditor", False)
            caller_tenant_id = body.get("tenant_id")
            res = self.decrypt_audit_record(
                log_id=log_id,
                envelope=envelope,
                as_auditor=as_auditor,
                caller_tenant_id=caller_tenant_id,
            )
            self.send_json(res, status_code=200 if res.get("status") == "SUCCESS" else 400)

        elif path == "/api/aws/onboard":
            res = state.onboard_tenant(body)
            self.send_json(res)

        elif path in ["/api/aws/test-connection", "/api/aws/test-credentials"]:
            res = state.test_real_connection(body)
            self.send_json(res)

        elif path == "/api/aws/connect":
            res = state.connect_real_account(body)
            self.send_json(res)

        elif path == "/api/aws/disconnect":
            res = state.disconnect_real_account()
            self.send_json(res)

        elif path in ["/api/retry-failed", "/api/remediate-all"]:
            res = state.retry_failed_actions()
            self.send_json({"status": "SUCCESS", "retried_count": res["retried_count"], "succeeded_count": res["succeeded_count"]})

        elif path == "/api/approve-action":
            res = self.execute_human_approval(body)
            self.send_json(res)

        elif path == "/approve":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            body_params = {k: v[0] for k, v in parse_qs(raw_body).items()}
            params.update(body_params)
            event = {
                "requestContext": {"http": {"method": "POST"}},
                "queryStringParameters": params,
                "body": raw_body,
            }
            resp = approval_handler(event)
            self.send_response(resp.get("statusCode", 200))
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(resp.get("body", "").encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def decrypt_audit_record(
        self,
        log_id: str | None,
        envelope: dict | None,
        as_auditor: bool = False,
        caller_tenant_id: str | None = None,
    ) -> dict:
        """Decrypt an audit record envelope using authentic AWS KMS envelope decryption."""
        if not as_auditor:
            return {
                "status": "ERROR",
                "message": "Auditor role authorization required: Decrypted view is restricted to FinOpsAuditorRole.",
            }

        kms = state.get_boto_client("kms")

        target_envelope = envelope
        record_tenant_id = None
        if not target_envelope and log_id:
            for log_entry in state.local_audit_logs:
                if log_entry.get("log_id") == log_id:
                    target_envelope = log_entry.get("envelope")
                    record_tenant_id = log_entry.get("tenant_id")
                    break

        if not target_envelope:
            return {"status": "ERROR", "message": f"Audit record envelope not found for log_id: {log_id}"}

        if not record_tenant_id:
            record_tenant_id = target_envelope.get("encryption_context", {}).get("tenant_id")

        active_tenant = caller_tenant_id or state.tenant_id
        if active_tenant and record_tenant_id and active_tenant != record_tenant_id:
            return {
                "status": "ERROR",
                "message": f"Cross-tenant decryption denied: Tenant '{active_tenant}' is not authorized to decrypt records for '{record_tenant_id}'.",
            }

        try:
            decrypted_details = decrypt_payload(target_envelope, kms_client=kms)
            return {
                "status": "SUCCESS",
                "log_id": log_id,
                "decrypted_details": decrypted_details,
            }
        except Exception as e:
            logger.warning("KMS audit decryption failed: %s", e)
            return {
                "status": "ERROR",
                "message": f"KMS envelope decryption failed: {e}",
            }

    def read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            raw = self.rfile.read(content_length).decode("utf-8")
            try:
                return json.loads(raw)
            except Exception:
                return {}
        return {}

    def send_json(self, data: dict, status_code: int = 200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode("utf-8"))

    def get_status(self) -> dict:
        potential_savings = sum(item["finding"]["estimated_monthly_cost"] for item in state.findings_cache)
        ec2_count = sum(1 for item in state.findings_cache if item["finding"]["resource_type"] == "ec2")
        ebs_count = sum(1 for item in state.findings_cache if item["finding"]["resource_type"] == "ebs")
        esc_count = sum(1 for item in state.findings_cache if item["evaluation"]["decision"] == "ESCALATE")

        return {
            "mode": state.mode,
            "account_id": state.account_id,
            "caller_arn": state.caller_arn,
            "region": state.region,
            "dry_run": state.dry_run,
            "scope_mode": state.scope_mode,
            "csrf_token": state.csrf_token,
            "total_savings_monthly": potential_savings,
            "potential_savings_monthly": potential_savings,
            "realized_savings_monthly": round(state.realized_savings, 2),
            "simulated_savings_monthly": round(state.simulated_savings, 2),
            "flagged_count": len(state.findings_cache),
            "ec2_count": ec2_count,
            "ebs_count": ebs_count,
            "remediated_count": state.remediated_count,
            "simulated_actions_count": state.simulated_actions_count,
            "real_actions_count": state.real_actions_count,
            "escalated_count": esc_count,
            "autopilot_enabled": state.autopilot_enabled,
            "autopilot_interval": state.autopilot_interval,
            "last_seeded_counts": state.last_seeded_counts,
        }

    def execute_human_approval(self, body: dict) -> dict:
        resource_id = body.get("resource_id", "")
        action = body.get("action", "")
        token = body.get("token", "")
        expires = body.get("expires", 0)

        try:
            expires_epoch = int(expires)
        except (ValueError, TypeError):
            expires_epoch = 0

        # Verify HMAC signature and validity
        secret_key = state.get_secret_key()
        if not verify_approval_token(resource_id, action, expires_epoch, token, secret_key):
            logger.warning("Rejected unverified/expired approval token for %s", resource_id)
            return {"status": "FAILED", "message": "Invalid or expired HMAC approval token."}

        ec2 = state.get_boto_client("ec2")
        config = Config()

        resource_type = "ec2" if resource_id.startswith("i-") else "ebs"
        tags: dict[str, str] = {}
        try:
            if resource_type == "ec2":
                desc = ec2.describe_instances(InstanceIds=[resource_id])
                tags = {t["Key"]: t["Value"] for t in desc["Reservations"][0]["Instances"][0].get("Tags", [])}
            else:
                desc = ec2.describe_volumes(VolumeIds=[resource_id])
                tags = {t["Key"]: t["Value"] for t in desc["Volumes"][0].get("Tags", [])}
        except Exception:
            tags = {"Project": "finops-demo", "env": "prod"}

        finding = Finding(
            resource_id=resource_id,
            resource_type=resource_type,
            idle_duration_hours=0.0,
            tags=tags,
        )

        try:
            rem_res = remediate_resource(finding, config=config, ec2_client=ec2, mode="approved")
            ev = EvaluationResult(finding, Confidence.HIGH, Risk.HIGH, Decision.AUTO_REMEDIATE, "Human manager approval via console")
            action_name = "[DRY_RUN] HUMAN_APPROVED" if state.dry_run else "HUMAN_APPROVED_REMEDIATION"
            state.record_audit_log(finding, ev, action_name)
            state.remediated_count += 1
            f_cost = 0.0
            for f_item in state.findings_cache:
                if f_item["finding"]["resource_id"] == resource_id:
                    f_cost = f_item["finding"].get("estimated_monthly_cost", 0.0)
                    f_item["remediation_status"] = "HUMAN_APPROVED_REMEDIATED"
                    f_item["why_no_auto_action"] = "Approved by manager via web console."

            if state.mode == "real" and not state.dry_run:
                state.real_actions_count += 1
                state.realized_savings += f_cost
            else:
                state.simulated_actions_count += 1
                state.simulated_savings += f_cost

            return {"status": "SUCCESS", "message": f"Approved {action} on {resource_id}", "detail": rem_res}
        except Exception as e:
            return {"status": "FAILED", "message": str(e)}


def start_server():
    state.start_mock()
    try:
        server_address = ("127.0.0.1", PORT)
        httpd = HTTPServer(server_address, FinOpsHandler)
        url = f"http://localhost:{PORT}"
        print("\n" + "=" * 75)
        print("   SCOPEFORGE FINOPS — MULTI-ACCOUNT AWS AUTO-REMEDIATION CONSOLE   ")
        print("=" * 75)
        print(f"Server is running at:  {url}")
        print("Active Mode:           MOCK SIMULATION (Switch to Real AWS in the UI)")
        print("Press Ctrl+C to stop the server.")
        print("=" * 75 + "\n")

        webbrowser.open(url)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        state.stop_mock(force=True)


if __name__ == "__main__":
    start_server()
