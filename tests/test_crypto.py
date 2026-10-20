"""
Tests for KMS Envelope Encryption — Milestone M3.

Covers:
    - Encrypt and decrypt roundtrip
    - Encryption context matching
    - Tamper detection (AES-GCM tag verification failure)
    - Missing required envelope fields error handling
"""

from __future__ import annotations

import base64
import boto3
import pytest
from moto import mock_aws

from src.crypto.envelope import decrypt_payload, encrypt_payload


@pytest.fixture
def kms_key():
    """Create a mock KMS key for testing."""
    with mock_aws():
        kms = boto3.client("kms", region_name="ap-south-1")
        key = kms.create_key(Description="FinOps Test Key")
        key_id = key["KeyMetadata"]["KeyId"]
        yield kms, key_id


class TestEnvelopeEncryption:
    """Test envelope encryption and decryption functionality."""

    @mock_aws
    def test_encrypt_decrypt_roundtrip(self):
        """Encrypting and then decrypting returns original data."""
        kms = boto3.client("kms", region_name="ap-south-1")
        key = kms.create_key(Description="Test Key")
        key_id = key["KeyMetadata"]["KeyId"]

        original_data = {
            "resource_id": "i-1234567890abcdef0",
            "action": "AUTO_REMEDIATED",
            "savings": 15.50,
            "nested": {"key": "value", "count": 42},
        }

        envelope = encrypt_payload(
            data=original_data,
            kms_key_id=key_id,
            kms_client=kms,
        )

        assert "ciphertext_b64" in envelope
        assert "encrypted_data_key_b64" in envelope
        assert "nonce_b64" in envelope
        assert envelope["kms_key_id"] == key_id

        decrypted = decrypt_payload(envelope=envelope, kms_client=kms)
        assert decrypted == original_data

    @mock_aws
    def test_encryption_context(self):
        """Encryption context must match during decryption."""
        kms = boto3.client("kms", region_name="ap-south-1")
        key = kms.create_key(Description="Test Key")
        key_id = key["KeyMetadata"]["KeyId"]

        data = {"secret": "confidential_finops_data"}
        context = {"company": "pixelforge", "env": "prod"}

        envelope = encrypt_payload(
            data=data,
            kms_key_id=key_id,
            kms_client=kms,
            encryption_context=context,
        )

        # Decrypt with correct context (embedded in envelope) succeeds
        decrypted = decrypt_payload(envelope=envelope, kms_client=kms)
        assert decrypted == data

    @mock_aws
    def test_tampered_ciphertext_fails(self):
        """Modifying ciphertext causes AES-GCM decryption failure."""
        kms = boto3.client("kms", region_name="ap-south-1")
        key = kms.create_key(Description="Test Key")
        key_id = key["KeyMetadata"]["KeyId"]

        data = {"important": "value"}
        envelope = encrypt_payload(data=data, kms_key_id=key_id, kms_client=kms)

        # Tamper with ciphertext bytes
        raw_ciphertext = base64.b64decode(envelope["ciphertext_b64"])
        tampered_ciphertext = bytearray(raw_ciphertext)
        tampered_ciphertext[0] ^= 0xFF  # Flip bits
        envelope["ciphertext_b64"] = base64.b64encode(bytes(tampered_ciphertext)).decode("utf-8")

        with pytest.raises(ValueError, match="AES-GCM decryption failed"):
            decrypt_payload(envelope=envelope, kms_client=kms)

    @mock_aws
    def test_missing_envelope_fields_raises_error(self):
        """Incomplete envelope raises ValueError."""
        kms = boto3.client("kms", region_name="ap-south-1")

        incomplete_envelope = {"ciphertext_b64": "abc"}

        with pytest.raises(ValueError, match="missing required field"):
            decrypt_payload(envelope=incomplete_envelope, kms_client=kms)

    @mock_aws
    def test_multi_tenant_kms_tenant_isolation(self):
        """Cross-tenant decryption fails: Tenant A's ciphertext cannot be decrypted under Tenant B's context."""
        kms = boto3.client("kms", region_name="ap-south-1")
        key = kms.create_key(Description="Platform CMK")
        key_id = key["KeyMetadata"]["KeyId"]

        tenant_a_data = {"resource_id": "i-0123456789abcdefa", "cost_saved": 45.0, "tenant": "tenant-alpha"}
        context_a = {"tenant_id": "tenant-alpha", "run_id": "run-001"}

        envelope_a = encrypt_payload(
            data=tenant_a_data,
            kms_key_id=key_id,
            kms_client=kms,
            encryption_context=context_a,
        )

        # Attacker tries to decrypt Tenant A's envelope with Tenant B's context
        tampered_envelope = dict(envelope_a)
        tampered_envelope["encryption_context"] = {"tenant_id": "tenant-beta", "run_id": "run-001"}

        with pytest.raises(ValueError, match="KMS decryption failed"):
            decrypt_payload(envelope=tampered_envelope, kms_client=kms)

    @mock_aws
    def test_customer_managed_cmk_support(self):
        """Encrypted payload under customer CMK key A cannot be decrypted by customer CMK key B."""
        kms = boto3.client("kms", region_name="ap-south-1")
        key_a = kms.create_key(Description="Customer CMK Alpha")["KeyMetadata"]["KeyId"]
        key_b = kms.create_key(Description="Customer CMK Beta")["KeyMetadata"]["KeyId"]

        data = {"tenant_config": "isolated-workload"}
        envelope = encrypt_payload(data=data, kms_key_id=key_a, kms_client=kms)

        # Decrypting with key_a works
        assert decrypt_payload(envelope=envelope, kms_client=kms) == data

        # Attempting to use key_b to decrypt envelope encrypted under key_a fails in KMS
        encrypted_data_key = base64.b64decode(envelope["encrypted_data_key_b64"])
        with pytest.raises(Exception):
            kms.decrypt(CiphertextBlob=encrypted_data_key, KeyId=key_b)

    @mock_aws
    def test_byok_disabled_key_fails_closed(self):
        """Disabling a BYOK customer KMS key fails closed: decrypt raises ValueError."""
        kms = boto3.client("kms", region_name="ap-south-1")
        key = kms.create_key(Description="BYOK Customer Key")
        key_id = key["KeyMetadata"]["KeyId"]

        data = {"tenant_secret": "confidential_workload_config"}
        envelope = encrypt_payload(data=data, kms_key_id=key_id, kms_client=kms)

        # Customer disables their key
        kms.disable_key(KeyId=key_id)

        # Attempting to decrypt must fail closed with ValueError
        with pytest.raises(ValueError, match="KMS decryption failed"):
            decrypt_payload(envelope=envelope, kms_client=kms)

