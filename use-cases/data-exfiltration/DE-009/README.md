# DE-009: CI secret printed into a PR comment

> CI secret printed into a PR comment

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** github-actions, any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `CI-SECRET-LEAK`, `OAUTH-TOKEN`
- **MITRE ATLAS:** AML.T0055, AML.T0086
- **OWASP ASI:** ASI02, ASI03

## Why it works

Echoing a secret into PR output exposes it to anyone who can read the pull request.

## Mitigations

- Never echo secrets.
- Mask secrets in CI logs and comments.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0067

> Payloads are **defanged** and for defensive testing only. Do not run them.
