# Azure deployment

SkillVenom runs on Azure App Service (Linux, Python 3.14, one Uvicorn worker). The
same application serves the site and the API. Investigation records and the
`statistics/totals.json` counter live in a private Blob container that the app reaches
with its system-assigned managed identity. There are no connection strings, storage keys,
publishing passwords, GitHub tokens, databases or language-model services.

## What gets deployed

[infra/main.bicep](../infra/main.bicep) (resource-group scope), parameters in
[infra/main.parameters.json](../infra/main.parameters.json):

| Resource | Configuration |
| --- | --- |
| App Service plan | Linux, `B1` (Always On) |
| Web app | `PYTHON|3.14`, HTTPS only, TLS 1.2, FTP off, FTP/SCM basic auth off, HTTP/2, health check `/healthz`, system-assigned identity, startup `uvicorn --workers 1 --no-proxy-headers` |
| Storage account | StorageV2 LRS, shared-key access **disabled**, anonymous blob access disabled, TLS 1.2, HTTPS only, OAuth by default |
| Blob container | `skillvenom-investigations`, private |
| Lifecycle rule | Deletes `investigations/` blobs 30 days after last modification; `statistics/` is kept |
| Blob service | Soft delete, container soft delete, versioning and change feed **off** so copies cannot outlive retention |
| Role assignment | *Storage Blob Data Contributor* for the web app identity, scoped to the container only |
| Log Analytics | 30-day retention; web app logs + metrics and blob read/write/delete audit logs |

App settings set by the template:

```text
ARCHIVE_BACKEND=azure
AZURE_STORAGE_ACCOUNT=<generated>
AZURE_STORAGE_CONTAINER=skillvenom-investigations
AZURE_ARCHIVE_RETENTION_CONFIRMED=true   # the lifecycle rule is part of the same template
TRUSTED_PROXY_HOPS=1                     # App Service front end appends X-Forwarded-For
SCM_DO_BUILD_DURING_DEPLOYMENT=true      # remote build installs requirements.txt
WEBSITES_PORT=8000
```

Indicative cost (westeurope, pay-as-you-go): App Service B1 is the main cost (roughly
USD 13/month); Storage, transactions and Log Analytics ingestion are typically a few
dollars at low traffic. Check the [pricing calculator](https://azure.microsoft.com/pricing/calculator/)
for your region and currency.

## 1. Provision and deploy (az CLI)

Prerequisites: Azure CLI 2.60+ (`az bicep` included), `zip`, `curl`, and an account with
*Contributor* + *User Access Administrator* (or *Owner*) on the target resource group,
because the template creates a role assignment.

```bash
az login
infra/deploy.sh --what-if        # preview (creates the resource group if missing)
infra/deploy.sh                  # provision + package + deploy + wait for /healthz
infra/deploy.sh --code-only      # later: redeploy code only
```

Override `RESOURCE_GROUP` (default `rg-skillvenom`), `LOCATION` (default `westeurope`)
or `AZURE_SUBSCRIPTION_ID` as environment variables. The first start may fail until the
new role assignment propagates (usually a few minutes); App Service restarts the app and
the script waits up to 10 minutes for `/healthz`.

[infra/package.sh](../infra/package.sh) builds the ZIP from only the runtime inputs:
`requirements.txt`, `scan_agents_md.py`, `credential_rules.json`, `SOURCES.md` and
`web/`. `.archive/`, `.env`, `.venv/`, `poc/`, tests and fixtures are never packaged.

## 2. Continuous deployment (GitHub Actions, OIDC)

[.github/workflows/deploy-azure.yml](../.github/workflows/deploy-azure.yml) runs the
Python, PowerShell-parity and JavaScript checks, then deploys on pushes to `main` that
touch runtime files (or manually). The deploy job is skipped until the repository is
configured:

```bash
RESOURCE_GROUP=rg-skillvenom infra/setup-github-oidc.sh azurekid/AgentTrap
```

This creates a Microsoft Entra application with a **federated credential** for
`repo:<owner>/<repo>:environment:production` (no client secret), grants it
*Website Contributor* on the web app only, creates the `production` environment and sets
the `AZURE_*` repository variables (identifiers, not secrets). Add required reviewers to
the `production` environment to gate releases. Infrastructure changes stay a manual
`infra/deploy.sh` step, so CI never holds role-assignment rights.

## 3. Public-service hardening

This deployment exposes App Service directly (HTTPS only). The app enforces body
limits, per-client and per-instance scan limits, two concurrent scans and isolated
scanner timeouts; these are single-process safety controls, not DDoS protection.
For higher exposure, add Azure Front Door Premium with WAF (managed rules, rate limits,
bot protection), restrict App Service access to the Front Door service tag and
`X-Azure-FDID`, and set `trustedProxyHops` to `2`. Configure budgets and alerts.

Network isolation (private endpoint for Blob + VNet integration) is not included in
this template; add it if your policy requires storage to be unreachable from the
internet. Shared-key access is already disabled, so Entra ID RBAC is the only data path.

## 4. Verify after deployment

- `/healthz` returns `{"status":"ok"}` over HTTPS; `/` shows the scanner.
- Upload `tests/benign/AGENTS.md`: no high-risk findings and no archive record.
- Run `python tools/fixtures.py /tmp/skillvenom-fixtures`, upload
  `/tmp/skillvenom-fixtures/tests/repo/.codex/config.toml`: `CODEX-FULL-ACCESS`, a private
  archive record under `investigations/`, and the retention notice. Repeat with the
  consent box unticked: report says *opted out* and no blob is written.
- Scan a small public GitHub repository; the report shows the pinned commit.
- Download the JSON report and confirm credential-shaped values are redacted.
- Anonymous access to the container is denied; no storage keys are in app settings.
- `az storage account management-policy show` lists the 30-day rule.
- Keep HTTP/APM body logging disabled. Exported reports and filenames may still be sensitive.
- Review legal basis, permitted investigation use, the pre-ticked consent default,
  deletion workflow and access audits (blob audit logs are in Log Analytics).

Investigators need their own *Storage Blob Data Reader* assignment on the container;
there is no public archive API.
