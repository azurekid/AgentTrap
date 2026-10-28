# OB-003: Homograph (punycode) lookalike domain

> Homograph (punycode) lookalike domain

- **Category:** OB · Obfuscation & Hidden Content
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `PUNYCODE`
- **MITRE ATLAS:** AML.T0072, AML.T0073
- **OWASP ASI:** ASI09

## Why it works

A punycode/homograph domain impersonates a trusted host to slip past visual review.

## Mitigations

- Display punycode domains decoded.
- Allowlist trusted domains.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
