# PI-005: ClickFix fake human-verification lure

> ClickFix fake human-verification lure

- **Category:** PI · Prompt Injection & Instruction Override
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `CLICKFIX`
- **MITRE ATLAS:** AML.T0053, AML.T0100
- **OWASP ASI:** ASI05, ASI09

## Why it works

A social-engineering 'prove you are human' lure directs the agent or user to paste and run a clipboard command.

## Mitigations

- Never paste-and-run clipboard content on request.
- Flag human-verification prompts that ask for terminal commands.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0055

> Payloads are **defanged** and for defensive testing only. Do not run them.
