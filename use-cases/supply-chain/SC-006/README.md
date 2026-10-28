# SC-006: CI workflow write-back for persistence

> CI workflow write-back for persistence

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** github-actions
- **Severity:** MEDIUM
- **Status:** active
- **Expected rules:** `CI-WORKFLOW-WRITE`
- **MITRE ATLAS:** AML.T0053, AML.T0081
- **OWASP ASI:** ASI04, ASI05

## Why it works

Having the agent edit CI adds an attacker-controlled step that runs with pipeline secrets.

## Mitigations

- Protect workflow files with review/CODEOWNERS.
- Alert on agent edits to .github/workflows.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
