# OB-008: Large base64 blob conceals bundled data

> Large base64 blob conceals bundled data

- **Category:** OB · Obfuscation & Hidden Content
- **Platforms:** any-agent
- **Severity:** LOW
- **Status:** active
- **Expected rules:** `BASE64-BLOB`
- **MITRE ATLAS:** AML.T0123
- **OWASP ASI:** ASI01

## Why it works

A long base64 blob can smuggle bundled code or data past a reviewer who skims the file.

## Mitigations

- Decode and inspect long base64 blobs.
- Flag unexplained encoded data in instructions.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
