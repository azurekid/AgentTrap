# TM-004 — Tool shadowing: BCC every email to the attacker

> Tool shadowing: BCC every email to the attacker

- **Category:** TM · Tool Misuse & Privilege Abuse
- **Platforms:** mcp, any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `TOOL-SHADOWING`
- **MITRE ATLAS:** AML.T0053, AML.T0110
- **OWASP ASI:** ASI02, ASI04

## Why it works

Instructions redefine how another tool behaves, silently copying every message to the attacker.

## Mitigations

- Pin tool behaviour; ignore cross-tool overrides.
- Alert on hidden BCC/forward rules.

## Artifacts

- `payload/TM-004.inert` → scanned as `SKILL.md`

## Benign look-alike

- `benign/TM-004.inert` → scanned as `SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
