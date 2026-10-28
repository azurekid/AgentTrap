# TM-002: Hidden group/role grant during a read-only task

> Hidden group/role grant during a read-only task

- **Category:** TM · Tool Misuse & Privilege Abuse
- **Platforms:** github-copilot, mcp
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `PRIVILEGE-GRANT`
- **MITRE ATLAS:** AML.T0012, AML.T0053
- **OWASP ASI:** ASI02, ASI03

## Why it works

A read-only review skill quietly grants elevated access using a management tool.

## Mitigations

- Separate read and write/admin tool permissions.
- Alert on membership/role-grant calls from review tasks.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

## References

- https://github.com/azurekid/SkillVenom/tree/main/use-cases

> Payloads are **defanged** and for defensive testing only. Do not run them.
