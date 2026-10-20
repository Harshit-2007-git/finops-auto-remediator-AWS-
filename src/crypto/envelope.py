"""
KMS Envelope Encryption module.

Uses AWS KMS GenerateDataKey to perform AES-256-GCM envelope encryption on
arbitrary dictionary payloads before storing them in DynamoDB.

Pattern:
    1. Call KMS GenerateDataKey(KeySpec='AES_256') -> (PlaintextDataKey, EncryptedDataKey)
    2. Encrypt plaintext payload JSON with AES-256-GCM using PlaintextDataKey + random 12-byte nonce
    3. Discard PlaintextDataKey from memory
    4. Store EncryptedDataKey + Nonce + Ciphertext in DynamoDB
    5. To read: KMS Decrypt(EncryptedDataKey) -> PlaintextDataKey -> AES-256-GCM Decrypt
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def encrypt_payload(
    data: dict[str, Any],
    kms_key_id: str,
    kms_client: Any = None,
    encryption_context: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Encrypt a dictionary payload using KMS envelope encryption with AES-256-GCM.

    Args:
        data: Dictionary payload to encrypt.
        kms_key_id: KMS Key ID or Alias ARN.
        kms_client: boto3 KMS client (created if None).
        encryption_context: Optional KMS encryption context dict.

    Returns:
        Dict containing:
            - ciphertext_b64: Base64-encoded encrypted payload
            - encrypted_data_key_b64: Base64-encoded KMS data key
            - nonce_b64: Base64-encoded 12-byte GCM nonce
            - kms_key_id: KMS Key ID used
            - encryption_context: Context passed to KMS
    """
    if kms_client is None:
        kms_client = boto3.client("kms")

    context = encryption_context or {}

    # Serialize payload to JSON
    json_bytes = json.dumps(data, sort_keys=True, default=str).encode("utf-8")

    # Step 1: Request data key from KMS
    logger.debug("Generating KMS data key for key ID %s", kms_key_id)
    key_params: dict[str, Any] = {
        "KeyId": kms_key_id,
        "KeySpec": "AES_256",
    }
    if context:
        key_params["EncryptionContext"] = context

    response = kms_client.generate_data_key(**key_params)

    plaintext_key = response["Plaintext"]
    encrypted_data_key = response["CiphertextBlob"]

    # Step 2: Encrypt with AES-256-GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(plaintext_key)
    ciphertext = aesgcm.encrypt(nonce, json_bytes, None)

    # Step 3: Base64 encode all binary components for transport / DB storage
    envelope = {
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "encrypted_data_key_b64": base64.b64encode(encrypted_data_key).decode("utf-8"),
        "nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "kms_key_id": kms_key_id,
        "encryption_context": context,
    }

    logger.info("Successfully encrypted payload with KMS key %s", kms_key_id)
    return envelope


def decrypt_payload(
    envelope: dict[str, Any],
    kms_client: Any = None,
) -> dict[str, Any]:
    """Decrypt a KMS envelope payload back into original dictionary.

    Args:
        envelope: Dict output from encrypt_payload containing b64 strings.
        kms_client: boto3 KMS client (created if None).

    Returns:
        Decrypted original dictionary payload.

    Raises:
        ValueError: If envelope structure is invalid or decryption fails.
    """
    if kms_client is None:
        kms_client = boto3.client("kms")

    required_fields = ["ciphertext_b64", "encrypted_data_key_b64", "nonce_b64"]
    for field in required_fields:
        if field not in envelope:
            raise ValueError(f"Invalid envelope: missing required field '{field}'")

    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    encrypted_data_key = base64.b64decode(envelope["encrypted_data_key_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    context = envelope.get("encryption_context", {})

    # Step 1: Decrypt data key using KMS
    # Verify key is enabled and available (fails closed if disabled or unavailable)
    key_id = envelope.get("kms_key_id")
    if key_id:
        try:
            desc = kms_client.describe_key(KeyId=key_id)
            if not desc.get("KeyMetadata", {}).get("Enabled", True):
                raise ValueError(f"KMS decryption failed: KMS key {key_id} is disabled")
        except Exception as k_err:
            if "disabled" in str(k_err).lower() or isinstance(k_err, ValueError):
                raise ValueError(f"KMS decryption failed: {k_err}") from k_err

    decrypt_params: dict[str, Any] = {
        "CiphertextBlob": encrypted_data_key,
    }
    if context:
        decrypt_params["EncryptionContext"] = context

    try:
        key_response = kms_client.decrypt(**decrypt_params)
    except Exception as e:
        logger.error("KMS Decrypt failed: %s", str(e))
        raise ValueError(f"KMS decryption failed: {e}") from e

    plaintext_key = key_response["Plaintext"]

    # Step 2: Decrypt payload using AES-256-GCM
    try:
        aesgcm = AESGCM(plaintext_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        logger.error("AES-GCM decryption failed: %s", str(e))
        raise ValueError(f"AES-GCM decryption failed (tampered data or wrong key): {e}") from e

    # Step 3: Deserialize JSON
    payload = json.loads(decrypted_bytes.decode("utf-8"))
    logger.info("Successfully decrypted KMS envelope payload")
    return payload
