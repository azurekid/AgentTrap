# SC-002: Authoritative 'you MUST install' nudge

> Authoritative 'you MUST install' nudge

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `AUTHORITATIVE-INSTALL`, `NPM-INSTALL`
- **MITRE ATLAS:** AML.T0010.001, AML.T0011.001
- **OWASP ASI:** ASI04

## Why it works

Framing an install as mandatory pressures the agent to add an unvetted (typosquatted) package.

## Mitigations

- Vet packages before install.
- Treat 'you must install' as a red flag.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0022

> Payloads are **defanged** and for defensive testing only. Do not run them.
