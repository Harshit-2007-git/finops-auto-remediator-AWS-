#!/usr/bin/env bash
# Teardown script for PixelForge Studios FinOps Demo
set -e

echo "=== Tearing Down FinOps Demo Environment ==="
python3 "$(dirname "$0")/teardown.py"
echo "=== Teardown Complete ==="
