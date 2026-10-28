# PA-002: Codex config grants full access and disables approvals

> Codex config grants full access and disables approvals

- **Category:** PA · Autonomy & Platform-Config Abuse
- **Platforms:** codex
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `CODEX-FULL-ACCESS`
- **MITRE ATLAS:** AML.T0081
- **OWASP ASI:** ASI03

## Why it works

danger-full-access with approval_policy=never removes the sandbox and all human confirmation.

## Mitigations

- Keep Codex sandbox on and approvals required.
- Flag danger-full-access in config.

## Artifacts

- `payload/.codex/config.toml` → scanned as `.codex/config.toml`

## Benign look-alike

- `benign/.codex/config.toml` → scanned as `.codex/config.toml`

> Payloads are **defanged** and for defensive testing only. Do not run them.
