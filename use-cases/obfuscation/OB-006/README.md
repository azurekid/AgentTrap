# OB-006: Base64 command blob decoded and piped to shell

> Base64 command blob decoded and piped to shell

- **Category:** OB · Obfuscation & Hidden Content
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `BASE64-PAYLOAD`
- **MITRE ATLAS:** AML.T0068, AML.T0123
- **OWASP ASI:** ASI01, ASI05

## Why it works

A base64 blob that decodes to a curl-pipe-sh command hides the payload from casual review.

## Mitigations

- Decode and inspect base64 blobs.
- Block decode-and-execute chains.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
