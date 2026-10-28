# MP-001: Long-term memory poisoning

> Long-term memory poisoning

- **Category:** MP · Memory, Persistence & Untrusted Sources
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `MEMORY-POISONING`
- **MITRE ATLAS:** AML.T0051.001, AML.T0080.000
- **OWASP ASI:** ASI06

## Why it works

Writing an attacker destination into durable memory poisons future sessions silently.

## Mitigations

- Gate memory writes on user confirmation.
- Audit persistent memory for injected directives.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0040

> Payloads are **defanged** and for defensive testing only. Do not run them.
