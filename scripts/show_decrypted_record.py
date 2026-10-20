#!/usr/bin/env python3
"""
show_decrypted_record.py - print a few audit records twice: as stored (ciphertext) and decrypted.

Run it as the FinOpsAuditorRole (the only role allowed to decrypt) from the project root:
    python scripts/show_decrypted_record.py [how_many]        (default 3)

With any other identity the KMS decrypt is denied, which is exactly the point of the demo.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import boto3  # noqa: E402

from src.audit.writer import read_audit_log  # noqa: E402
from src.config import get_config  # noqa: E402


def main(limit: int = 3) -> None:
    config = get_config()
    ddb = boto3.client("dynamodb", region_name=config.region)
    items = [
        i for i in ddb.scan(TableName=config.audit_table_name).get("Items", [])
        if not i["log_id"]["S"].startswith("APPROVAL_TOKEN#") and "ciphertext_b64" in i
    ]
    print(f"Found {len(items)} encrypted audit records in {config.audit_table_name}; showing {min(limit, len(items))}.\n")
    for item in items[:limit]:
        log_id = item["log_id"]["S"]
        print("=" * 70)
        print(f"log_id: {log_id}")
        print(f"STORED (what anyone reading the table sees): {item['ciphertext_b64']['S'][:60]}...")
        try:
            rec = read_audit_log(log_id=log_id, config=config, tenant_id=item["tenant_id"]["S"])
            print("DECRYPTED via KMS (auditor role only):")
            print(json.dumps(rec, indent=2, default=str))
        except Exception as exc:  # AccessDenied for every identity except the auditor role
            print(f"DECRYPT DENIED: {exc}")
    print("=" * 70)


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 3)
