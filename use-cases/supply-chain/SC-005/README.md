# SC-005: Worm propagation into every instruction file

> Worm propagation into every instruction file

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `WORM-PROPAGATION`
- **MITRE ATLAS:** AML.T0061
- **OWASP ASI:** ASI08, ASI10

## Why it works

Self-replicating instructions spread the payload across repositories.

## Mitigations

- Alert on self-copying instructions.
- Treat instruction files as code under review.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
