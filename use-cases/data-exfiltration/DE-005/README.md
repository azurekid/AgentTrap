# DE-005: Cloud instance-metadata credential theft

> Cloud instance-metadata credential theft

- **Category:** DE · Data Exfiltration & Covert Channels
- **Platforms:** any-agent
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `CLOUD-METADATA`, `RAW-IP-URL`
- **MITRE ATLAS:** AML.T0055, AML.T0072, AML.T0089
- **OWASP ASI:** ASI02, ASI03

## Why it works

Reading the link-local metadata endpoint harvests temporary cloud credentials of the runner.

## Mitigations

- Block 169.254.169.254 egress (IMDSv2, hop limit).
- Use workload identity, not metadata scraping.

## Artifacts

- `payload/AGENTS.md` → scanned as `AGENTS.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
