# PI-001: Classic ignore-previous-instructions override

> Classic ignore-previous-instructions override

- **Category:** PI · Prompt Injection & Instruction Override
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `PROMPT-INJECTION`
- **MITRE ATLAS:** AML.T0051.001
- **OWASP ASI:** ASI01

## Why it works

A prompt-injection string tries to replace the agent's standing instructions with attacker goals and to coerce a fixed, misleading response.

## Mitigations

- Treat instruction files as untrusted input.
- Pin and review agent instructions; alert on override phrasing.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0043

> Payloads are **defanged** and for defensive testing only. Do not run them.
