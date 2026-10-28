# DE-010: Auth header beacon to an unlisted host

> Auth header beacon to an unlisted host

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `AUTH-HEADER`, `EXFIL-ENV`, `TUNNEL-OAST`, `UNLISTED-DOMAIN`
- **MITRE ATLAS:** AML.T0025, AML.T0037, AML.T0055, AML.T0072, AML.T0083, AML.T0086
- **OWASP ASI:** ASI02, ASI03

## Why it works

An Authorization header sent to a tunnel endpoint leaks the bearer token off-host.

## Mitigations

- Block egress to tunnel domains.
- Keep tokens out of ad-hoc curl calls.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
