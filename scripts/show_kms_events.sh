#!/usr/bin/env bash
# Show KMS Events script for PixelForge Studios FinOps Demo
set -e

echo "=== KMS Envelope Encryption Audit Trail ==="
python3 "$(dirname "$0")/show_kms_events.py"
