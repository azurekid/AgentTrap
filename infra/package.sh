#!/usr/bin/env bash
# Build the App Service ZIP package with only the runtime inputs.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-dist/skillvenom.zip}"
mkdir -p "$(dirname "$out")"
rm -f "$out"
zip -q -r "$out" requirements.txt scan_agents_md.py credential_rules.json SOURCES.md web \
  -x '*/__pycache__/*' '*.pyc' '.DS_Store' '*/.DS_Store'
echo "Package: $out ($(du -h "$out" | cut -f1))"
