# CE-003: Reverse shell over /dev/tcp and netcat

> Reverse shell over /dev/tcp and netcat

- **Category:** CE · Command Execution & Remote Payloads
- **Platforms:** any-agent
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `REVERSE-SHELL`
- **MITRE ATLAS:** AML.T0050, AML.T0072
- **OWASP ASI:** ASI05

## Why it works

A reverse shell gives the attacker interactive control of the runner.

## Mitigations

- Block outbound connections to arbitrary hosts/ports.
- Alert on /dev/tcp and nc -e patterns.

## Artifacts

- `payload/CE-003.inert` → scanned as `SKILL.md`

## Benign look-alike

- `benign/CE-003.inert` → scanned as `SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
