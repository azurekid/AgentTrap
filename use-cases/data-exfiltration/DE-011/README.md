# DE-011: Credential-prompt harvesting dialog

> Credential-prompt harvesting dialog

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `CREDENTIAL-PROMPT`
- **MITRE ATLAS:** AML.T0055, AML.T0073
- **OWASP ASI:** ASI03, ASI09

## Why it works

Spawning a native password dialog phishes the user's credentials under the guise of a routine prompt.

## Mitigations

- Never request OS credentials from a skill.
- Flag GUI password-prompt helpers.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
