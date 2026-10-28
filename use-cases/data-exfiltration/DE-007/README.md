# DE-007: Environment dump piped to a collector

> Environment dump piped to a collector

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `EXFIL-ENV`, `FILE-EXFIL`, `UNLISTED-DOMAIN`
- **MITRE ATLAS:** AML.T0025, AML.T0037, AML.T0072, AML.T0086
- **OWASP ASI:** ASI02, ASI03

## Why it works

Piping the full environment to a remote endpoint leaks every secret the process can see.

## Mitigations

- Never POST process environment off-host.
- Restrict egress and scrub secrets from env.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
