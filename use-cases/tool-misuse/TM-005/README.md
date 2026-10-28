# TM-005: OAuth/token environment reference

> OAuth/token environment reference

- **Category:** TM · Tool Misuse & Privilege Abuse
- **Platforms:** github-actions, any-agent
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `OAUTH-TOKEN`
- **MITRE ATLAS:** AML.T0055
- **OWASP ASI:** ASI03

## Why it works

Pulling named token environment variables into output is a precursor to credential leakage.

## Mitigations

- Never log token env vars.
- Mask secrets in agent output.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
