"""Regenerate the rule table and rule references in Scan-AgentsMd.ps1 from scan_agents_md.py.

Usage: python tools/sync_powershell_rules.py [--check]
The Python scanner is the source of truth; --check exits 1 when the PowerShell copy differs.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import scan_agents_md as scanner  # noqa: E402

TARGET = ROOT / "Scan-AgentsMd.ps1"
RULES_START, RULES_END = "        Rules         = @(\n", "\n        )\n    }\n}"
REFS_START, REFS_END = "        RuleRefs      = @{\n", "\n        }\n"


def quote(text):
    return text.replace("'", "''")


def render_rules():
    lines = ["        Rules         = @("]
    for rule, severity, message, rx in scanner.RULES:
        pattern = quote(rx.pattern)
        expr = f"(& $rx '{pattern}')" if rx.flags & re.I else f"[regex]'{pattern}'"
        lines.append(f"            , @('{rule}', '{severity}', '{quote(message)}',\n                {expr})")
    return "\n".join(lines)


def render_refs():
    items = [f"'{rule}' = '{ref}'" for rule, ref in sorted(scanner.RULE_REFS.items())]
    rows = ["; ".join(items[i:i + 4]) for i in range(0, len(items), 4)]
    return REFS_START + "\n".join("            " + row for row in rows)


def replace(text, start, end, body):
    i = text.index(start)
    j = text.index(end, i)
    return text[:i] + body + text[j:]


def main():
    current = TARGET.read_text(encoding="utf-8")
    updated = replace(current, RULES_START, RULES_END, render_rules())
    updated = replace(updated, REFS_START, REFS_END, render_refs())
    if "--check" in sys.argv:
        if updated != current:
            print("Scan-AgentsMd.ps1 is out of date; run python tools/sync_powershell_rules.py")
            return 1
        return 0
    TARGET.write_text(updated, encoding="utf-8")
    print(f"Synced {len(scanner.RULES)} rules and {len(scanner.RULE_REFS)} references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
