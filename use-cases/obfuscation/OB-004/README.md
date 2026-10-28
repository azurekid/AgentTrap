# OB-004: HTML comment hides an assistant-only instruction

> HTML comment hides an assistant-only instruction

- **Category:** OB · Obfuscation & Hidden Content
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `CRED-FILES`, `HIDDEN-COMMENT`
- **MITRE ATLAS:** AML.T0037, AML.T0051.001, AML.T0055, AML.T0068
- **OWASP ASI:** ASI01, ASI03

## Why it works

HTML comments are invisible in rendered Markdown but still read by the model, hiding a credential-theft instruction.

## Mitigations

- Surface HTML comments to reviewers.
- Treat hidden comments as untrusted instructions.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
