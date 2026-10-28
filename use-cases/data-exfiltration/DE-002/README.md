# DE-002: DNS-tunnel exfiltration of a secret

> DNS-tunnel exfiltration of a secret

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `DNS-EXFIL`, `KNOWN-IOC`, `OAUTH-TOKEN`
- **MITRE ATLAS:** AML.T0010, AML.T0025, AML.T0055, AML.T0086
- **OWASP ASI:** ASI02, ASI03, ASI04

## Why it works

Embedding a secret as a DNS subdomain leaks it through resolver logs even when outbound HTTP is blocked.

## Mitigations

- Restrict agent network egress.
- Never interpolate secrets into hostnames.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
