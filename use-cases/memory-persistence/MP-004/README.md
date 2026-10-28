# MP-004: Instruction file in an untrusted Downloads folder

> Instruction file in an untrusted Downloads folder

- **Category:** MP · Memory, Persistence & Untrusted Sources
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `UNTRUSTED-LOCATION`
- **MITRE ATLAS:** AML.T0051.001, AML.T0078
- **OWASP ASI:** ASI01

## Why it works

An AGENTS.md in a web-writable folder (Downloads/Desktop/tmp) is auto-loaded by agents launched there, even if its text looks benign.

## Mitigations

- Do not run agents from Downloads/Desktop/tmp.
- Warn when instruction files load from untrusted paths.

## Artifacts

- `payload/Users/example/Downloads/AGENTS.md` → scanned as `/Users/example/Downloads/AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
