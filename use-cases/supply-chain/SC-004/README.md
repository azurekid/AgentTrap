# SC-004: Registry/mirror redirection to a suspicious TLD

> Registry/mirror redirection to a suspicious TLD

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `NPM-INSTALL`, `NPX-YES`, `REGISTRY-REDIRECT`, `SUSPICIOUS-TLD`
- **MITRE ATLAS:** AML.T0010.001, AML.T0011.001, AML.T0053, AML.T0072
- **OWASP ASI:** ASI02, ASI04

## Why it works

Repointing the npm registry to an attacker mirror lets every install deliver malware.

## Mitigations

- Pin the registry.
- Alert on registry/mirror changes and suspicious TLDs.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
