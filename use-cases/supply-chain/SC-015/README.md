# SC-015: Tampered signed skill

> Validate NVIDIA-style OMS signature result invalid with an explicitly configured sample-only trust root.

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** regression
- **Expected rules:** `PROMPT-INJECTION`
- **Expected OMS signature:** invalid
- **Test trust only:** Configure `use-cases/signature-test-root.pem` explicitly in an isolated test trust store. Never trust this root in production.
- **Scope:** Upload the whole payload folder. This is not an NVIDIA-signed artifact and reputation is not assessed.

## Why it works

Cryptographic identity and byte integrity are independent of security findings. These local test certificates are never trusted automatically and do not impersonate NVIDIA.

## Mitigations

- Configure the sample root only in isolated tests. Never use it as a production publisher trust anchor.
- Review findings even when a signature verifies. Upload all package members with their relative paths.

## Artifacts

- `payload/skills/oms-review/SKILL.md` → scanned as `skills/oms-review/SKILL.md`
- `payload/skills/oms-review/references/notes.md` → scanned as `skills/oms-review/references/notes.md`
- `payload/skills/oms-review/skill.oms.sig` → scanned as `skills/oms-review/skill.oms.sig`

## References

- https://docs.nvidia.com/skills/signing-agent-skills

> Payloads are **defanged** and for defensive testing only. Do not run them.
