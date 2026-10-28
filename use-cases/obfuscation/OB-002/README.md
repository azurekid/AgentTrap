# OB-002: Variation-selector smuggling

> Variation-selector smuggling

- **Category:** OB · Obfuscation & Hidden Content
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `VARIATION-SELECTOR-SMUGGLING`
- **MITRE ATLAS:** AML.T0051.001, AML.T0068
- **OWASP ASI:** ASI01

## Why it works

Runs of variation selectors encode hidden data that survives copy/paste while staying invisible.

## Mitigations

- Normalise and strip stray variation selectors.
- Flag non-emoji selector runs.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
