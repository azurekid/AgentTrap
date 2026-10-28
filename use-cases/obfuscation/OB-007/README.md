# OB-007: Obfuscated bootstrap: echo base64 | base64 -d | sh

> Obfuscated bootstrap: echo base64 | base64 -d | sh

- **Category:** OB · Obfuscation & Hidden Content
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `OBFUSCATION`
- **MITRE ATLAS:** AML.T0050, AML.T0123
- **OWASP ASI:** ASI01, ASI05

## Why it works

Chaining base64 decode into a shell hides the real command behind an encoding step.

## Mitigations

- Block decode-to-shell pipelines.
- Require plain, reviewable setup commands.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
