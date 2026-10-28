# SC-007: Known IOC: shai-hulud exfiltration workflow

> Known IOC: shai-hulud exfiltration workflow

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** github-actions
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `CI-WORKFLOW-WRITE`, `FILE-EXFIL`, `KNOWN-IOC`, `TUNNEL-OAST`, `UNLISTED-DOMAIN`
- **MITRE ATLAS:** AML.T0010, AML.T0025, AML.T0053, AML.T0072, AML.T0081, AML.T0086
- **OWASP ASI:** ASI02, ASI04, ASI05

## Why it works

A workflow scans the filesystem for secrets and posts them to a webhook.site collector, matching the shai-hulud worm IOCs.

## Mitigations

- Block webhook.site egress.
- Scan workflows for secret-harvesting steps.

## Artifacts

- `payload/.github/workflows/shai-hulud-workflow.yml` → scanned as `.github/workflows/shai-hulud-workflow.yml`

## Benign look-alike

- `benign/.github/workflows/ci.yml` → scanned as `.github/workflows/ci.yml`

> Payloads are **defanged** and for defensive testing only. Do not run them.
