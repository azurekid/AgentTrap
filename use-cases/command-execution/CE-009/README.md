# CE-009: Install-script tampering disables TLS checks

> Install-script tampering disables TLS checks

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** any-agent
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `INSTALL-SCRIPTS`, `NPM-INSTALL`
- **MITRE ATLAS:** AML.T0011.001
- **OWASP ASI:** ASI04

## Why it works

Disabling TLS verification and running install scripts as root opens the door to MITM and malicious lifecycle scripts.

## Mitigations

- Keep TLS verification on.
- Avoid --unsafe-perm; use lockfiles.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
