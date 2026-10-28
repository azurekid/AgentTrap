# CE-002: Self-propagating remote command loop

> Self-propagating remote command loop

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `REMOTE-COMMANDS`, `UNLISTED-DOMAIN`, `WORM-PROPAGATION`
- **MITRE ATLAS:** AML.T0051.001, AML.T0061, AML.T0072, AML.T0108
- **OWASP ASI:** ASI01, ASI02, ASI05, ASI08, ASI10

## Why it works

A persistent C2 fetch-and-execute loop turns the agent into a scheduled backdoor that also spreads itself.

## Mitigations

- Block periodic remote-command execution.
- Alert on self-copying instruction text.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

## References

- https://atlas.mitre.org/studies/AML.CS0051

> Payloads are **defanged** and for defensive testing only. Do not run them.
