# PI-003: Jailbreak persona (DAN / unrestricted mode)

> Jailbreak persona (DAN / unrestricted mode)

- **Category:** PI · Prompt Injection & Instruction Override
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `JAILBREAK-PERSONA`
- **MITRE ATLAS:** AML.T0051.001, AML.T0054
- **OWASP ASI:** ASI01

## Why it works

Persona jailbreaks tell the model it is a new, unrestricted character to shed its safety alignment before issuing harmful requests.

## Mitigations

- Reject persona-switch instructions from untrusted files.
- Keep safety policies independent of conversation role-play.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
