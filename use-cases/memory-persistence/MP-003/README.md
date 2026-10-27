# MP-003 — Host persistence via crontab and shell rc

> Host persistence via crontab and shell rc

- **Category:** MP · Memory, Persistence & Untrusted Sources
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `PERSISTENCE`
- **MITRE ATLAS:** AML.T0081
- **OWASP ASI:** ASI10

## Why it works

Cron @reboot and shell-rc edits re-launch the payload across sessions and reboots.

## Mitigations

- Alert on crontab and rc-file edits.
- Monitor persistence locations.

## Artifacts

- `payload/MP-003.inert` → scanned as `AGENTS.md`

## Benign look-alike

- `benign/MP-003.inert` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
