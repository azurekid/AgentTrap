# CE-007: Privilege escalation to root group

> Privilege escalation to root group

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `PRIVILEGE-ESCALATION`
- **MITRE ATLAS:** AML.T0050, AML.T0053
- **OWASP ASI:** ASI03

## Why it works

Granting passwordless sudo, group membership and a setuid shell establishes persistent root access.

## Mitigations

- Deny privilege-management commands to agents.
- Alert on NOPASSWD, usermod -aG and setuid changes.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
