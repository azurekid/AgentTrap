# MP-002: Conditional memory write on trigger phrase

> Conditional memory write on trigger phrase

- **Category:** MP · Memory, Persistence & Untrusted Sources
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `PROMPT-INJECTION`
- **MITRE ATLAS:** AML.T0051.001
- **OWASP ASI:** ASI01

## Why it works

A delayed, trigger-gated memory write hides the poisoning until a benign user reply fires it.

## Mitigations

- Require explicit consent for memory writes.
- Flag trigger-conditioned silent actions.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0038

> Payloads are **defanged** and for defensive testing only. Do not run them.
