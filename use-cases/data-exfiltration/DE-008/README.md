# DE-008: Local file exfiltration of MCP config

> Local file exfiltration of MCP config

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** cursor, any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `FILE-EXFIL`, `SUSPICIOUS-TLD`
- **MITRE ATLAS:** AML.T0025, AML.T0072, AML.T0086
- **OWASP ASI:** ASI02

## Why it works

Uploading a local config file leaks server endpoints and any embedded tokens.

## Mitigations

- Block uploads of dotfiles/configs.
- Treat `@file` curl bodies as exfiltration.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0045

> Payloads are **defanged** and for defensive testing only. Do not run them.
