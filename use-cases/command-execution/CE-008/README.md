# CE-008: Anti-forensics: clear history and logs

> Anti-forensics: clear history and logs

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `ANTI-FORENSICS`
- **MITRE ATLAS:** AML.T0050, AML.T0101
- **OWASP ASI:** ASI02, ASI10

## Why it works

Clearing shell history and audit logs is indicator removal that hides the attack from responders.

## Mitigations

- Protect audit logs from agent writes.
- Alert on history/log clearing.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
