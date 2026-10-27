#!/usr/bin/env bash
# Build the App Service ZIP package with only the runtime inputs.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-dist/skillvenom.zip}"
mkdir -p "$(dirname "$out")"
rm -f "$out"
inputs=(requirements.txt scan_agents_md.py credential_rules.json SOURCES.md web)
if command -v zip >/dev/null; then
  zip -q -r "$out" "${inputs[@]}" -x '*/__pycache__/*' '*.pyc' '.DS_Store' '*/.DS_Store'
else
  # Fallback for shells without zip (same contents, same exclusions).
  python3 - "$out" "${inputs[@]}" <<'PY'
import sys, zipfile
from pathlib import Path
out, *inputs = sys.argv[1:]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
    for item in map(Path, inputs):
        files = [item] if item.is_file() else sorted(p for p in item.rglob("*") if p.is_file())
        for path in files:
            if "__pycache__" in path.parts or path.suffix == ".pyc" or path.name == ".DS_Store":
                continue
            archive.write(path, path.as_posix())
PY
fi
echo "Package: $out ($(du -h "$out" | cut -f1))"
