#!/usr/bin/env bash
# Seed script for PixelForge Studios FinOps Demo
set -e

echo "=== Seeding FinOps Demo Environment ==="
python3 "$(dirname "$0")/seed.py"
echo "=== Seeding Complete ==="
