# DE-006: Browser-login and crypto-wallet theft

> Browser-login and crypto-wallet theft

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `WALLET-BROWSER-THEFT`
- **MITRE ATLAS:** AML.T0037, AML.T0113
- **OWASP ASI:** ASI03

## Why it works

Named browser-credential and wallet files are classic infostealer targets.

## Mitigations

- Deny agent access to browser profiles and wallet files.
- Alert on reads of known credential stores.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
