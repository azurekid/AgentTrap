# TM-001: Agent tool exfiltrates secrets to another repository

> Agent tool exfiltrates secrets to another repository

- **Category:** TM · Tool Misuse & Privilege Abuse
- **Platforms:** github-copilot, mcp
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `TOOL-EXFIL`
- **MITRE ATLAS:** AML.T0053, AML.T0086
- **OWASP ASI:** ASI02

## Why it works

A granted write tool is abused to move secrets into an attacker-controlled repository, so the exfiltration rides a legitimate capability.

## Mitigations

- Constrain tool scope to the working repo.
- Alert when tools target another repo/org/account.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

## References

- https://github.com/azurekid/SkillVenom/tree/main/use-cases

> Payloads are **defanged** and for defensive testing only. Do not run them.
