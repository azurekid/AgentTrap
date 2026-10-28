# SC-008: Plain-HTTP dependency download

> Plain-HTTP dependency download

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `PLAIN-HTTP`
- **MITRE ATLAS:** AML.T0072
- **OWASP ASI:** ASI02

## Why it works

Fetching over plain HTTP allows on-path tampering of the downloaded content.

## Mitigations

- Require HTTPS.
- Reject plain-HTTP downloads of code or config.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
