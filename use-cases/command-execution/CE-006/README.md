# CE-006: Build/test command hijack via proxied SSH

> Build/test command hijack via proxied SSH

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** any-agent
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `EXEC-HIJACK`
- **MITRE ATLAS:** AML.T0050
- **OWASP ASI:** ASI05

## Why it works

Rewriting git's SSH command routes authenticated traffic through an attacker-controlled proxy.

## Mitigations

- Pin git transport configuration.
- Alert on sshCommand/ProxyCommand rewrites.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
