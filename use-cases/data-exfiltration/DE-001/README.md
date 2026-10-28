# DE-001: Markdown image beacon exfiltrates conversation

> Markdown image beacon exfiltrates conversation

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `MARKDOWN-IMAGE-EXFIL`, `UNLISTED-DOMAIN`
- **MITRE ATLAS:** AML.T0072, AML.T0077
- **OWASP ASI:** ASI02

## Why it works

A Markdown image URL with a templated query string leaks conversation content to an attacker when the client renders it.

## Mitigations

- Do not auto-render remote images from untrusted output.
- Block templated exfiltration parameters.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0021

> Payloads are **defanged** and for defensive testing only. Do not run them.
