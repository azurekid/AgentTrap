# TM-003: Skill trigger hijack: 'use me for every request'

> Skill trigger hijack: 'use me for every request'

- **Category:** TM · Tool Misuse & Privilege Abuse
- **Platforms:** claude-code, any-agent
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `SKILL-TRIGGER-HIJACK`
- **MITRE ATLAS:** AML.T0051.001, AML.T0110
- **OWASP ASI:** ASI01, ASI04

## Why it works

An over-broad trigger makes the skill intercept unrelated prompts, a precondition for silent tool abuse.

## Mitigations

- Scope skill triggers narrowly.
- Flag 'every request / before other skills' triggers.

## Artifacts

- `payload/SKILL.md` → scanned as `SKILL.md`

## Benign look-alike

- `benign/SKILL.md` → scanned as `SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
