"""
Unit and integration tests for the FinOps web console backend (web/server.py).

Covers:
    - Status API returning mock and region details
    - Re-seeding via /api/seed without duplicating resources (W1 fix)
    - Real HTTPServer on localhost:0 testing POST /api/seed 5 consecutive times (idempotency)
    - Closed-loop auto-remediation and separated counters via POST /api/scan
    - Autopilot toggle lifecycle via POST /api/autopilot
    - HMAC approval action with verification (M3 / W3 / security fixes)
    - Rejection of invalid or forged HMAC approval tokens
    - Dry-run mode toggling via /api/config
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer

import pytest
from moto import mock_aws
import botocore.exceptions
from unittest.mock import patch

from src.crypto.envelope import decrypt_payload
from web.server import FinOpsHandler, FinOpsState, state


@pytest.fixture(autouse=True)
def reset_server_state():
    """Ensure clean mock state before each web test."""
    state.start_mock()
    yield
    state.toggle_autopilot(False)
    state.stop_mock()


class TestWebServerLogic:
    """Test web server state management, closed-loop execution, and real HTTP endpoints."""

    def test_mock_state_initialization(self):
        """Web state initializes in mock mode with canonical 8 resources and zero real AWS dependencies."""
        assert state.mode == "mock"
        assert state.dry_run is True
        assert state.account_id == "123456789012 (Demo Simulation)"
        assert state.last_seeded_counts["total"] == 8
        assert state.last_seeded_counts["instances"] == 5
        assert state.last_seeded_counts["volumes"] == 3

    def test_reseed_does_not_duplicate_resources(self):
        """Repeated seeding resets state rather than piling up duplicate instances (W1 fix)."""
        state.run_scan()
        count_first = len(state.findings_cache)
        assert count_first == 6

        # Reset & Re-scan
        state.reset_environment()
        count_second = len(state.findings_cache)

        # Resource count should be identical, NOT doubled
        assert count_second == count_first

    def test_http_seed_five_times_idempotency_on_real_socket(self):
        """Start real HTTPServer on localhost:0, call POST /api/seed 5 consecutive times via urllib.

        Assert:
            - Every response returns HTTP 200 with status SUCCESS.
            - Response contains exactly 8 resources, 5 instances, 3 volumes, 0 duplicates.
            - Direct EC2 describe_instances returns exactly 5 instances (0 duplicates).
            - Direct EC2 describe_volumes returns exactly 3 volumes (0 duplicates).
        """
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            url = f"http://127.0.0.1:{port}/api/seed"
            ec2 = state.get_boto_client("ec2")

            for attempt in range(5):
                req = urllib.request.Request(
                    url,
                    data=b"{}",
                    headers={
                        "Content-Type": "application/json",
                        "X-FinOps-Token": state.csrf_token,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req) as resp:
                    assert resp.status == 200
                    data = json.loads(resp.read().decode("utf-8"))
                    assert data["status"] == "SUCCESS"
                    assert data["resource_count"] == 8
                    assert data["instances_count"] == 5
                    assert data["volumes_count"] == 3
                    assert data["duplicate_count"] == 0

                # Direct AWS API inspection via boto3
                reservations = ec2.describe_instances()["Reservations"]
                instances = [
                    inst for r in reservations for inst in r["Instances"]
                    if inst["State"]["Name"] != "terminated"
                ]
                assert len(instances) == 5, f"Attempt {attempt+1}: Expected 5 instances, got {len(instances)}"

                demo_volumes = ec2.describe_volumes(
                    Filters=[{"Name": "tag:Project", "Values": ["finops-demo"]}]
                )["Volumes"]
                assert len(demo_volumes) == 3, f"Attempt {attempt+1}: Expected 3 demo volumes, got {len(demo_volumes)}"
                all_volumes = ec2.describe_volumes()["Volumes"]
                assert len(all_volumes) == 8, f"Attempt {attempt+1}: Expected 8 total volumes (5 root + 3 demo), got {len(all_volumes)}"

        finally:
            server.shutdown()
            server.server_close()

    def test_scan_endpoint_closed_loop_execution_and_counters(self):
        """POST /api/scan executes closed-loop actions and updates counters."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Re-seed first
            seed_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/seed",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(seed_req) as resp:
                assert resp.status == 200

            # Trigger scan
            scan_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(scan_req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "SUCCESS"
                assert len(data["findings"]) == 6

            # Status API returns updated counters
            status_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status")
            with urllib.request.urlopen(status_req) as resp:
                st = json.loads(resp.read().decode("utf-8"))
                assert st["flagged_count"] == 6
                assert st["remediated_count"] >= 3  # dev-api-01, qa-runner-01, vol-dev-orphan
                assert st["simulated_actions_count"] >= 3
                assert st["escalated_count"] == 2  # prod-report-01, vol-prod-orphan
                assert st["potential_savings_monthly"] > 0
                assert st["simulated_savings_monthly"] > 0
                assert st["realized_savings_monthly"] == 0.0

        finally:
            server.shutdown()
            server.server_close()

    def test_autopilot_endpoint_and_lifecycle(self):
        """Autopilot can be toggled via POST /api/autopilot."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            url = f"http://127.0.0.1:{port}/api/autopilot"

            # Enable autopilot
            req_on = urllib.request.Request(
                url,
                data=json.dumps({"enabled": True, "interval": 10}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req_on) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["autopilot"]["enabled"] is True

            # Disable autopilot
            req_off = urllib.request.Request(
                url,
                data=json.dumps({"enabled": False}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req_off) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["autopilot"]["enabled"] is False

        finally:
            state.toggle_autopilot(False)
            server.shutdown()
            server.server_close()

    def test_human_approval_with_valid_hmac_token(self):
        """Approving action executes successfully when HMAC token is valid."""
        handler_instance = FinOpsHandler.__new__(FinOpsHandler)

        # Create an instance in mock EC2
        ec2 = state.get_boto_client("ec2")
        resp = ec2.run_instances(
            ImageId="ami-12345678",
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": "prod-approved-instance"},
                        {"Key": "Project", "Value": "finops-demo"},
                        {"Key": "env", "Value": "prod"},
                        {"Key": "owner", "Value": "alice@pixelforge.io"},
                    ],
                }
            ],
        )
        instance_id = resp["Instances"][0]["InstanceId"]

        expires = int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp())
        secret_key = state.get_secret_key()
        from src.escalation.handler import generate_approval_token
        token = generate_approval_token(instance_id, "STOP", expires, secret_key)

        body = {
            "resource_id": instance_id,
            "action": "STOP",
            "token": token,
            "expires": expires,
        }

        result = handler_instance.execute_human_approval(body)
        assert result["status"] == "SUCCESS"
        assert instance_id in result["message"]

    def test_human_approval_rejects_tampered_token(self):
        """Approval fails and rejects request if token signature is forged or tampered."""
        handler_instance = FinOpsHandler.__new__(FinOpsHandler)

        body = {
            "resource_id": "i-fake-12345678",
            "action": "STOP",
            "token": "deadbeef12345678badtoken",
            "expires": int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp()),
        }

        result = handler_instance.execute_human_approval(body)
        assert result["status"] == "FAILED"
        assert "Invalid or expired" in result["message"]

    def test_human_approval_rejects_expired_token(self):
        """Approval fails and rejects request if token timestamp has passed."""
        handler_instance = FinOpsHandler.__new__(FinOpsHandler)

        secret_key = state.get_secret_key()
        expired_ts = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        from src.escalation.handler import generate_approval_token
        token = generate_approval_token("i-test-expired", "STOP", expired_ts, secret_key)

        body = {
            "resource_id": "i-test-expired",
            "action": "STOP",
            "token": token,
            "expires": expired_ts,
        }

        result = handler_instance.execute_human_approval(body)
        assert result["status"] == "FAILED"
        assert "Invalid or expired" in result["message"]

    def test_post_without_csrf_token_returns_403(self):
        """POST /api/* without X-FinOps-Token header is rejected with HTTP 403."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 403
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "CSRF token" in err_body["message"]
        finally:
            server.shutdown()
            server.server_close()

    def test_post_with_invalid_csrf_token_returns_403(self):
        """POST /api/* with an invalid X-FinOps-Token header is rejected with HTTP 403."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={
                    "Content-Type": "application/json",
                    "X-FinOps-Token": "invalid_csrf_token_value_12345678",
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 403
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "CSRF token" in err_body["message"]
        finally:
            server.shutdown()
            server.server_close()

    def test_post_with_invalid_host_header_returns_403(self):
        """Requests with non-localhost Host header are rejected with HTTP 403."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/status",
                headers={"Host": "evil-attacker-site.com"},
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 403
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "Host" in err_body["message"]
        finally:
            server.shutdown()
            server.server_close()

    def test_post_without_json_content_type_returns_415(self):
        """POST /api/* without application/json Content-Type is rejected with HTTP 415."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"raw_text_payload",
                headers={
                    "Content-Type": "text/plain",
                    "X-FinOps-Token": state.csrf_token,
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req)
            assert exc_info.value.code == 415
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "Content-Type must be application/json" in err_body["message"]
        finally:
            server.shutdown()
            server.server_close()

    def test_security_headers_present_and_wildcard_cors_removed(self):
        """Server sends security headers (CSP, nosniff, DENY, no-referrer) and removes wildcard CORS."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status")
            with urllib.request.urlopen(req) as resp:
                headers = dict(resp.headers)
                assert resp.status == 200
                assert "Content-Security-Policy" in headers
                assert "'self'" in headers["Content-Security-Policy"]
                assert headers.get("X-Content-Type-Options") == "nosniff"
                assert headers.get("X-Frame-Options") == "DENY"
                assert headers.get("Referrer-Policy") == "no-referrer"
                assert "Access-Control-Allow-Origin" not in headers
        finally:
            server.shutdown()
            server.server_close()

    def test_csrf_token_exposed_in_status_and_endpoint(self):
        """GET /api/status and GET /api/csrf-token expose the active session CSRF token."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/csrf-token") as resp:
                data = json.loads(resp.read().decode("utf-8"))
                assert data["csrf_token"] == state.csrf_token

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status") as resp:
                st = json.loads(resp.read().decode("utf-8"))
                assert st["csrf_token"] == state.csrf_token
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_logs_contain_only_ciphertext_envelope(self):
        """Audit logs store only KMS ciphertext envelope and do not leak plaintext details in memory/API."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Trigger scan to generate audit logs
            scan_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(scan_req) as resp:
                assert resp.status == 200

            # Inspect audit logs returned by API
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/audit-logs") as resp:
                data = json.loads(resp.read().decode("utf-8"))
                logs = data["logs"]
                assert len(logs) > 0

                for log_entry in logs:
                    assert "envelope" in log_entry
                    assert "ciphertext_b64" in log_entry["envelope"]
                    assert "encrypted_data_key_b64" in log_entry["envelope"]
                    assert "nonce_b64" in log_entry["envelope"]
                    # Plaintext details MUST NOT be stored or returned
                    assert "details" not in log_entry
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_decrypt_endpoint_calls_kms_successfully(self):
        """POST /api/audit-logs/decrypt uses authentic KMS kms:Decrypt and returns decrypted details."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Run scan to create genuine audit entries
            scan_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(scan_req) as resp:
                assert resp.status == 200

            target_log = state.local_audit_logs[0]
            decrypt_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/audit-logs/decrypt",
                data=json.dumps({"log_id": target_log["log_id"], "envelope": target_log["envelope"], "as_auditor": True}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(decrypt_req) as resp:
                assert resp.status == 200
                res = json.loads(resp.read().decode("utf-8"))
                assert res["status"] == "SUCCESS"
                assert "decrypted_details" in res
                details = res["decrypted_details"]
                assert "finding" in details
                assert "evaluation" in details
                assert "action_taken" in details
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_decrypt_tampered_ciphertext_fails(self):
        """Tampered ciphertext fails AES-GCM verification and returns HTTP 400."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Run scan
            scan_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(scan_req) as resp:
                assert resp.status == 200

            target_log = state.local_audit_logs[0]
            tampered_envelope = dict(target_log["envelope"])
            # Corrupt ciphertext bytes
            tampered_envelope["ciphertext_b64"] = base64.b64encode(b"corrupted_bad_ciphertext_blob_12345").decode("utf-8")

            decrypt_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/audit-logs/decrypt",
                data=json.dumps({"log_id": target_log["log_id"], "envelope": tampered_envelope, "as_auditor": True}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(decrypt_req)
            assert exc_info.value.code == 400
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "failed" in err_body["message"].lower()
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_decrypt_tampered_context_fails(self):
        """Tampered encryption context fails KMS decryption and returns HTTP 400."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            scan_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(scan_req) as resp:
                assert resp.status == 200

            target_log = state.local_audit_logs[0]
            tampered_envelope = dict(target_log["envelope"])
            # Tamper the run_id in encryption context within same tenant so KMS decrypt fails on context mismatch
            tampered_envelope["encryption_context"] = {"tenant_id": "pixelforge", "run_id": "attacker-tampered-run"}

            decrypt_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/audit-logs/decrypt",
                data=json.dumps({"log_id": target_log["log_id"], "envelope": tampered_envelope, "as_auditor": True}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(decrypt_req)
            assert exc_info.value.code == 400
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "failed" in err_body["message"].lower() or "denied" in err_body["message"].lower()
        finally:
            server.shutdown()
            server.server_close()

    def test_happy_path_http_requests_log_no_warnings_or_errors(self, caplog):
        """Happy-path HTTP operations (seed, scan, decrypt) emit zero WARNING or ERROR logs."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            with caplog.at_level(logging.WARNING):
                # 1. Seed
                seed_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/seed",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(seed_req) as resp:
                    assert resp.status == 200

                # 2. Scan
                scan_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/scan",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(scan_req) as resp:
                    assert resp.status == 200

                # 3. Status
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status") as resp:
                    assert resp.status == 200

                # 4. Decrypt
                target_log = state.local_audit_logs[0]
                decrypt_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/audit-logs/decrypt",
                    data=json.dumps({"log_id": target_log["log_id"], "envelope": target_log["envelope"], "as_auditor": True}).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(decrypt_req) as resp:
                    assert resp.status == 200

            warn_err_logs = [r for r in caplog.records if r.levelno >= logging.WARNING]
            assert warn_err_logs == [], f"Unexpected warnings/errors: {[r.message for r in warn_err_logs]}"
        finally:
            server.shutdown()
            server.server_close()

    def test_cross_account_onboard_endpoint(self):
        """POST /api/aws/onboard generates >=32 char ExternalId and stores KMS-encrypted tenant config."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/onboard",
                data=json.dumps({"tenant_name": "Acme Studios", "tenant_id": "acme-studios"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "SUCCESS"
                assert len(data["external_id"]) >= 32
                assert "platform_account_id" in data
                assert data["template_path"] == "onboarding/finops-cross-account-role.yaml"

            # Verify tenant config is envelope-encrypted at rest
            assert "acme-studios" in state.tenant_registry
            stored_envelope = state.tenant_registry["acme-studios"]
            assert "ciphertext_b64" in stored_envelope
            assert "encrypted_data_key_b64" in stored_envelope
            assert "nonce_b64" in stored_envelope
            assert stored_envelope["encryption_context"] == {"tenant_id": "acme-studios", "type": "tenant_config"}

            # Verify decrypted content matches original
            decrypted = decrypt_payload(stored_envelope)
            assert decrypted["tenant_id"] == "acme-studios"
            assert decrypted["tenant_name"] == "Acme Studios"
            assert decrypted["external_id"] == data["external_id"]
        finally:
            server.shutdown()
            server.server_close()

    def test_connect_rejects_short_external_id(self):
        """POST /api/aws/connect rejects ExternalId shorter than 32 characters for confused deputy protection."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            payload = {
                "auth_method": "role",
                "role_arn": "arn:aws:iam::123456789012:role/FinOpsScannerRole",
                "external_id": "short-token-12345",
                "tenant_id": "tenant-short",
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/connect",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "ERROR"
                assert "at least 32 characters" in data["message"]
        finally:
            server.shutdown()
            server.server_close()

    def test_least_privilege_self_check_denies_admin_role(self):
        """POST /api/aws/test-connection rejects roles that allow iam:ListUsers (admin violation)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            payload = {
                "auth_method": "role",
                "role_arn": "arn:aws:iam::123456789012:role/FinOpsAdminRole",
                "external_id": "a" * 40,
                "tenant_id": "tenant-admin",
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/test-connection",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "ERROR"
                assert "least-privilege violation" in data["message"].lower()
        finally:
            server.shutdown()
            server.server_close()

    def test_connect_assumes_role_and_runs_scan(self):
        """POST /api/aws/connect assumes tenant role, switches to real mode, scans, and disconnects cleanly."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        orig_make_api_call = botocore.client.BaseClient._make_api_call

        def custom_api_call(self, operation_name, kwargs):
            if operation_name == "ListUsers":
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
                    "ListUsers",
                )
            return orig_make_api_call(self, operation_name, kwargs)

        try:
            with patch("botocore.client.BaseClient._make_api_call", new=custom_api_call):
                payload = {
                    "auth_method": "role",
                    "role_arn": "arn:aws:iam::222233334444:role/FinOpsScannerRole",
                    "external_id": "b" * 40,
                    "tenant_id": "tenant-alpha",
                    "scope_mode": "tagged",
                    "dry_run": True,
                    "kms_option": "platform",
                }
                connect_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/aws/connect",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(connect_req) as resp:
                    assert resp.status == 200
                    data = json.loads(resp.read().decode("utf-8"))
                    assert data["status"] == "SUCCESS"
                    assert data["account_id"] == "222233334444"
                    assert data["tenant_id"] == "tenant-alpha"

                # Verify GET /api/aws/status returns real mode & tenant info
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/aws/status") as resp:
                    status_data = json.loads(resp.read().decode("utf-8"))
                    assert status_data["mode"] == "real"
                    assert status_data["tenant_id"] == "tenant-alpha"
                    assert status_data["account_id"] == "222233334444"

                # Disconnect returns to mock mode
                disc_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/aws/disconnect",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(disc_req) as resp:
                    assert resp.status == 200
                    disc_data = json.loads(resp.read().decode("utf-8"))
                    assert disc_data["mode"] == "mock"
                    assert state.mode == "mock"
        finally:
            state.disconnect_real_account()
            server.shutdown()
            server.server_close()

    def test_scope_all_forces_dry_run(self):
        """Connecting with scope_mode='all' overrides dry_run to True for production safety."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        orig_make_api_call = botocore.client.BaseClient._make_api_call

        def custom_api_call(self, operation_name, kwargs):
            if operation_name == "ListUsers":
                raise botocore.exceptions.ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
                    "ListUsers",
                )
            return orig_make_api_call(self, operation_name, kwargs)

        try:
            with patch("botocore.client.BaseClient._make_api_call", new=custom_api_call):
                payload = {
                    "auth_method": "role",
                    "role_arn": "arn:aws:iam::555566667777:role/FinOpsScannerRole",
                    "external_id": "c" * 40,
                    "tenant_id": "tenant-scope-all",
                    "scope_mode": "all",
                    "dry_run": False,  # User requested active remediation on ALL
                    "kms_option": "platform",
                }
                connect_req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/aws/connect",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                    method="POST",
                )
                with urllib.request.urlopen(connect_req) as resp:
                    assert resp.status == 200
                    data = json.loads(resp.read().decode("utf-8"))
                    assert data["status"] == "SUCCESS"
                    assert data["scope_mode"] == "all"
                    assert data["dry_run"] is True  # Enforced!
                    assert state.dry_run is True
        finally:
            state.disconnect_real_account()
            server.shutdown()
            server.server_close()

    def test_zero_forbidden_credential_keys_in_codebase(self):
        """Zero occurrences of secret_access_key, access_key_id, inputSecretKey, inputAccessKey in web/ and src/."""
        import pathlib
        base_dir = pathlib.Path(__file__).resolve().parent.parent
        forbidden = ["secret_access_key", "access_key_id", "inputSecretKey", "inputAccessKey"]
        violations = []

        for check_dir in [base_dir / "web", base_dir / "src"]:
            for file_path in check_dir.rglob("*"):
                if file_path.is_file() and file_path.suffix in [".py", ".html", ".js", ".css"]:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for term in forbidden:
                        if term in content:
                            violations.append(f"{file_path.name}: contains forbidden term '{term}'")

        assert violations == [], f"Found forbidden credential keys in codebase: {violations}"

    def test_audit_spam_elimination_on_consecutive_scans(self):
        """Three consecutive no-change scans add 0 rows to audit logs (A5.1)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # 1. Reset environment
            reset_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/seed",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
            )
            with urllib.request.urlopen(reset_req) as resp:
                assert resp.status == 200

            # 2. First scan records initial findings
            scan_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/scan",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
            )
            with urllib.request.urlopen(scan_req) as resp:
                assert resp.status == 200

            # Check audit log count
            audit_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/audit-logs")
            with urllib.request.urlopen(audit_req) as resp:
                initial_logs = json.loads(resp.read().decode("utf-8"))["logs"]
                initial_count = len(initial_logs)
                assert initial_count > 0

            # 3. Perform 3 consecutive scans without environment change
            for _ in range(3):
                scan_req2 = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/scan",
                    data=b"{}",
                    headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                )
                with urllib.request.urlopen(scan_req2) as resp:
                    assert resp.status == 200

            # Verify audit log count remains identical (0 new rows added)
            with urllib.request.urlopen(audit_req) as resp:
                final_logs = json.loads(resp.read().decode("utf-8"))["logs"]
                assert len(final_logs) == initial_count, f"Expected {initial_count} logs, got {len(final_logs)} (audit spam detected)"

        finally:
            server.shutdown()
            server.server_close()

    def test_savings_counters_dry_run_zero_realized(self):
        """Status after Reset in dry-run shows realized_savings_monthly == 0.0 with 0 real actions (A5.2)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            # Reset environment
            reset_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/seed",
                data=b"{}",
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
            )
            with urllib.request.urlopen(reset_req) as resp:
                assert resp.status == 200

            # Query status
            status_req = urllib.request.Request(f"http://127.0.0.1:{port}/api/status")
            with urllib.request.urlopen(status_req) as resp:
                st = json.loads(resp.read().decode("utf-8"))
                assert st["realized_savings_monthly"] == 0.0
                assert st["real_actions_count"] == 0
                assert st["potential_savings_monthly"] > 0
                assert st["simulated_savings_monthly"] > 0
        finally:
            server.shutdown()
            server.server_close()

    def test_connect_account_requires_kms_option(self):
        """POST /api/aws/connect rejects connection without a KMS option (A1)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            payload = {
                "auth_method": "role",
                "role_arn": "arn:aws:iam::123456789012:role/FinOpsScannerRole",
                "external_id": "e" * 40,
                "tenant_id": "tenant-nokms",
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/connect",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "ERROR"
                assert "KMS encryption choice is required" in data["message"]
        finally:
            server.shutdown()
            server.server_close()

    def test_connect_account_byok_disabled_key_fails(self):
        """POST /api/aws/connect fails closed if BYOK KMS key is disabled (A1)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            kms = state.get_boto_client("kms")
            key = kms.create_key(Description="Disabled Customer BYOK Key")
            key_id = key["KeyMetadata"]["KeyId"]
            kms.disable_key(KeyId=key_id)

            payload = {
                "auth_method": "role",
                "role_arn": "arn:aws:iam::123456789012:role/FinOpsScannerRole",
                "external_id": "f" * 40,
                "tenant_id": "tenant-byok-disabled",
                "kms_option": "byok",
                "byok_key_arn": key_id,
            }
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/connect",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                data = json.loads(resp.read().decode("utf-8"))
                assert data["status"] == "ERROR"
                assert "disabled or unavailable" in data["message"].lower()
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_decrypt_requires_auditor_role(self):
        """POST /api/audit-logs/decrypt rejects requests without as_auditor=True (A3)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            state.run_scan()
            target_log = state.local_audit_logs[0]

            decrypt_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/audit-logs/decrypt",
                data=json.dumps({"log_id": target_log["log_id"], "envelope": target_log["envelope"], "as_auditor": False}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(decrypt_req)
            assert exc_info.value.code == 400
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "auditor role authorization required" in err_body["message"].lower()
        finally:
            server.shutdown()
            server.server_close()

    def test_audit_decrypt_cross_tenant_denied(self):
        """POST /api/audit-logs/decrypt rejects decrypting a tenant record from a different tenant (A1)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            state.run_scan()
            target_log = state.local_audit_logs[0]

            # Request decryption specifying a caller tenant different from the record's tenant
            decrypt_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/audit-logs/decrypt",
                data=json.dumps({
                    "log_id": target_log["log_id"],
                    "envelope": target_log["envelope"],
                    "as_auditor": True,
                    "tenant_id": "tenant-unauthorized-intruder",
                }).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(decrypt_req)
            assert exc_info.value.code == 400
            err_body = json.loads(exc_info.value.read().decode("utf-8"))
            assert "cross-tenant decryption denied" in err_body["message"].lower()
        finally:
            server.shutdown()
            server.server_close()

    def test_offline_multi_tenant_linking(self):
        """Link two mock tenants offline with distinct KMS key choices and verify multi-tenant isolation (A4)."""
        server = HTTPServer(("127.0.0.1", 0), FinOpsHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            kms = state.get_boto_client("kms")
            beta_cmk = kms.create_key(Description="Tenant Beta BYOK CMK")["KeyMetadata"]["KeyId"]

            # 1. Link Tenant Alpha (Platform key)
            payload_alpha = {
                "auth_method": "role",
                "role_arn": "arn:aws:iam::111122223333:role/FinOpsScannerRole",
                "external_id": "a" * 40,
                "tenant_id": "tenant-alpha",
                "kms_option": "platform",
                "mock_simulation": True,
            }
            req_alpha = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/connect",
                data=json.dumps(payload_alpha).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req_alpha) as resp:
                assert resp.status == 200
                data_alpha = json.loads(resp.read().decode("utf-8"))
                assert data_alpha["status"] == "SUCCESS"
                assert data_alpha["tenant_id"] == "tenant-alpha"
                assert state.tenant_kms_choice.get("tenant-alpha") == "platform"

            # 2. Link Tenant Beta (BYOK key)
            payload_beta = {
                "auth_method": "role",
                "role_arn": "arn:aws:iam::444455556666:role/FinOpsScannerRole",
                "external_id": "b" * 40,
                "tenant_id": "tenant-beta",
                "kms_option": "byok",
                "byok_key_arn": beta_cmk,
                "mock_simulation": True,
            }
            req_beta = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/aws/connect",
                data=json.dumps(payload_beta).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-FinOps-Token": state.csrf_token},
                method="POST",
            )
            with urllib.request.urlopen(req_beta) as resp:
                assert resp.status == 200
                data_beta = json.loads(resp.read().decode("utf-8"))
                assert data_beta["status"] == "SUCCESS"
                assert data_beta["tenant_id"] == "tenant-beta"
                assert state.tenant_kms_choice.get("tenant-beta") == "byok"
                assert state.tenant_kms_keys.get("tenant-beta") == beta_cmk

        finally:
            state.disconnect_real_account()
            server.shutdown()
            server.server_close()
