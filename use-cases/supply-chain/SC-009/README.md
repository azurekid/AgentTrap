# SC-009: Credentials embedded in a clone URL

> Credentials embedded in a clone URL

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `SECRET-URL`, `URL-CREDENTIALS`
- **MITRE ATLAS:** AML.T0055, AML.T0083
- **OWASP ASI:** ASI03

## Why it works

Inline userinfo credentials in a URL leak into logs and shell history.

## Mitigations

- Use credential helpers, not inline userinfo.
- Flag user:pass@ URLs.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
