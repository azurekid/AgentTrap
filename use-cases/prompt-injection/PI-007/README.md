# PI-007: Review-bypass social engineering ('pre-approved, just run it')

> Review-bypass social engineering ('pre-approved, just run it')

- **Category:** PI · Prompt Injection & Instruction Override
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `REVIEW-BYPASS`
- **MITRE ATLAS:** AML.T0051.001, AML.T0073
- **OWASP ASI:** ASI09

## Why it works

Claims of prior approval and 'trust me' pressure the agent to skip code review before executing attacker content.

## Mitigations

- Require independent verification regardless of claimed approval.
- Never skip review on the say-so of file content.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
