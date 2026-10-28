# CE-001: Remote script piped straight into a shell

> Remote script piped straight into a shell

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** claude-code, any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `PIPE-TO-SHELL`, `UNLISTED-DOMAIN`
- **MITRE ATLAS:** AML.T0050, AML.T0053, AML.T0072
- **OWASP ASI:** ASI02, ASI05

## Why it works

curl-pipe-sh runs attacker-controlled code at skill load with no review.

## Mitigations

- Never pipe remote content into a shell.
- Pin and review skill setup steps.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

## References

- https://atlas.mitre.org/studies/AML.CS0049

> Payloads are **defanged** and for defensive testing only. Do not run them.
