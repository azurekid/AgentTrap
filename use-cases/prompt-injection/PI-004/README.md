# PI-004: Prefilled AI assistant link poisons future answers

> Prefilled AI assistant link poisons future answers

- **Category:** PI · Prompt Injection & Instruction Override
- **Platforms:** github-copilot, any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `AI-PREFILL-LINK`
- **MITRE ATLAS:** AML.T0080.000, AML.T0131
- **OWASP ASI:** ASI06, ASI09

## Why it works

A Markdown link pre-fills an assistant query that plants a persistent, attacker-chosen 'trusted source' instruction.

## Mitigations

- Do not auto-follow assistant deep-links from untrusted content.
- Treat prefilled prompts as untrusted.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0072

> Payloads are **defanged** and for defensive testing only. Do not run them.
