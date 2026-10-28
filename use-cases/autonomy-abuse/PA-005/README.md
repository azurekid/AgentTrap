# PA-005: Gemini CLI trust and auto-accept disabled

> Gemini CLI trust and auto-accept disabled

- **Category:** PA · Autonomy & Platform-Config Abuse
- **Platforms:** gemini-cli
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `GEMINI-TRUST-OFF`
- **MITRE ATLAS:** AML.T0081
- **OWASP ASI:** ASI03

## Why it works

Disabling folder trust and enabling autoAccept removes Gemini CLI's execution safeguards.

## Mitigations

- Keep folderTrust on and autoAccept off.
- Review .gemini/settings.json.

## Artifacts

- `payload/.gemini/settings.json` → scanned as `.gemini/settings.json`

## Benign look-alike

- `benign/.gemini/settings.json` → scanned as `.gemini/settings.json`

> Payloads are **defanged** and for defensive testing only. Do not run them.
