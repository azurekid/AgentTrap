# CR-001: Config file ships live-shaped API tokens

> Config file ships live-shaped API tokens

- **Category:** CR · Hardcoded Credentials & Secrets
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `SECRET-AI-API`, `SECRET-ASSIGNMENT`
- **MITRE ATLAS:** AML.T0055, AML.T0083
- **OWASP ASI:** ASI03

## Why it works

Embedding real-shaped bot and API tokens in a committed config leaks them to anyone who clones the repo.

## Mitigations

- Use a secret manager.
- Scan for credential shapes in config.

## Artifacts

- `payload/skills/clawdbot/config.json` → scanned as `skills/clawdbot/config.json`

## References

- https://atlas.mitre.org/studies/AML.CS0048

> Payloads are **defanged** and for defensive testing only. Do not run them.
