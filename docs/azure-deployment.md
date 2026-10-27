# Azure deployment

SkillVenom is deployed with **Bicep** and the **Azure CLI**, and updated by a
**GitHub Actions** workflow that signs in to Azure through OpenID Connect (OIDC).
No Azure Developer CLI (`azd`), connection strings, storage keys, publishing
passwords or client secrets are used.

| File | Purpose |
| --- | --- |
| [infra/main.bicep](../infra/main.bicep) | All Azure resources (resource-group scope) |
| [infra/main.parameters.json](../infra/main.parameters.json) | Region, SKU, runtime and retention settings |
| [infra/deploy.sh](../infra/deploy.sh) | Preview, provision and deploy from your machine or Azure Cloud Shell |
| [infra/package.sh](../infra/package.sh) | Builds the ZIP with only the runtime files |
| [infra/deploy-code.sh](../infra/deploy-code.sh) | Uploads the ZIP asynchronously and waits for the build and `/healthz` |
| [infra/setup-github-oidc.sh](../infra/setup-github-oidc.sh) | One-time setup for keyless GitHub deployments |
| [.github/workflows/deploy-azure.yml](../.github/workflows/deploy-azure.yml) | Test, deploy and smoke-test on push to `main` |

## Architecture

```text
 Browser ──HTTPS──▶ App Service (Linux, Python 3.14, 1 Uvicorn worker)
                      │  system-assigned managed identity
                      ▼  Storage Blob Data Contributor (container scope)
                    Storage account (shared keys off, no public access)
                      └─ skillvenom-investigations/
                           ├─ investigations/…   deleted after 30 days (lifecycle rule)
                           └─ statistics/totals.json   aggregate counts, kept
 App Service logs/metrics + Blob audit logs ──▶ Log Analytics workspace (30 days)
```

The application serves the site and the API. Public GitHub, GitLab and Azure DevOps repositories (and private ones with a per-request token) are read from
`api.github.com` and `raw.githubusercontent.com` without a token.

## What the template creates

| Resource | Configuration |
| --- | --- |
| App Service plan | Linux, `B1` (Always On) |
| Web app | `PYTHON|3.14`; HTTPS only; TLS 1.2; HTTP/2; FTP and FTP/SCM basic auth disabled; remote debugging off; health check `/healthz`; system-assigned identity; startup `python -m uvicorn web.app:app --host 0.0.0.0 --port 8000 --workers 1 --no-proxy-headers` |
| Storage account | StorageV2, `Standard_LRS`; shared-key access **disabled**; anonymous blob access disabled; OAuth by default; TLS 1.2; HTTPS only |
| Blob service | Blob and container soft delete, versioning and change feed **off**, so no copies outlive the retention period |
| Blob container | `skillvenom-investigations`, private |
| Lifecycle rule | Deletes blobs under `skillvenom-investigations/investigations/` 30 days after last modification |
| Role assignment | *Storage Blob Data Contributor* for the web app identity, on the container only |
| Log Analytics | Web app logs and metrics; blob read/write/delete audit logs |

Names are `app-`, `asp-`, `log-` and `st` + prefix + an 8-character suffix derived
from the resource group, e.g. `app-skillvenom-ab12cd34`.

### Parameters

| Parameter | Default | Notes |
| --- | --- | --- |
| `location` | `westeurope` | Also settable with `LOCATION` in `deploy.sh` |
| `namePrefix` | `skillvenom` | 3–12 characters |
| `appServiceSku` | `B1` | `B1`, `B2`, `B3`, `P0v3`, `P1v3` |
| `pythonVersion` | `3.14` | Must be listed by `az webapp list-runtimes --os linux` |
| `archiveContainerName` | `skillvenom-investigations` | |
| `archiveRetentionDays` | `30` | Lifecycle deletion age; keep in line with the site's retention notice |
| `logRetentionDays` | `30` | Log Analytics retention |
| `trustedProxyHops` | `1` | Proxies appending `X-Forwarded-For`; `2` if Front Door is added |

### App settings

```text
ARCHIVE_BACKEND=azure
AZURE_STORAGE_ACCOUNT=<generated>
AZURE_STORAGE_CONTAINER=skillvenom-investigations
AZURE_ARCHIVE_RETENTION_CONFIRMED=true   # the lifecycle rule is in the same template
TRUSTED_PROXY_HOPS=1                     # App Service front end appends X-Forwarded-For
SCM_GITLAB_HOSTS= / SCM_AZDO_HOSTS=      # optional self-managed hosts (Bicep: gitlabHosts, azureDevOpsHosts)
SCM_DO_BUILD_DURING_DEPLOYMENT=true      # remote build installs requirements.txt
WEBSITES_PORT=8000
PYTHONUNBUFFERED=1
```

### Cost

App Service B1 is the main cost (roughly USD 13/month pay-as-you-go). Storage,
transactions and Log Analytics ingestion are typically a few dollars a month at low
traffic. Confirm with the [pricing calculator](https://azure.microsoft.com/pricing/calculator/)
for your region and currency, and set a budget alert on the resource group.

## 1. Prerequisites

- Bash (macOS, Linux, WSL/Git Bash on Windows, or [Azure Cloud Shell](#2a-deploy-from-azure-cloud-shell-no-local-tools))
  with `curl` and `zip` (or Python 3, used when `zip` is missing).
- Azure CLI, signed in with `az login` (tested with 2.77; `az bicep` installs on first use).
- On the target resource group (or subscription): *Owner*, or *Contributor* plus
  *User Access Administrator*, because the template creates a role assignment.
- For the GitHub setup only: the GitHub CLI (`gh auth login`) with admin rights on the
  repository, and permission to create Microsoft Entra app registrations.

## 2. First deployment

Run from the repository root:

```bash
az login
az account set --subscription "<subscription name or id>"

infra/deploy.sh --what-if     # creates the resource group if missing, then previews changes
infra/deploy.sh               # provision, package, deploy, wait for /healthz
```

`deploy.sh` reads these optional environment variables:

| Variable | Default |
| --- | --- |
| `RESOURCE_GROUP` | `rg-skillvenom` |
| `LOCATION` | `westeurope` |
| `AZURE_SUBSCRIPTION_ID` | current `az account` |

For example: `RESOURCE_GROUP=rg-skillvenom-test LOCATION=northeurope infra/deploy.sh`.

What `deploy.sh` does:

1. Creates the resource group (tag `application=SkillVenom`).
2. Deploys `main.bicep` as deployment `skillvenom-<UTC timestamp>`.
3. Runs `package.sh`, which zips only `requirements.txt`, `scan_agents_md.py`,
   `credential_rules.json`, `SOURCES.md` and `web/` (no `__pycache__`, tests, fixtures,
   `poc/`, `.venv/`, `.archive/` or `.env`) into `dist/skillvenom.zip`.
4. Runs `deploy-code.sh`, which uploads the ZIP with `az webapp deploy --type zip --async true`.
   App Service then builds it remotely (Oryx installs `requirements.txt`; about 4 minutes
   the first time, faster afterwards).
5. Polls the Kudu deployment status every 15 seconds and stops with the build log if the
   build fails. After a successful build it waits until `/healthz` is OK and `/` contains
   the scanner, then prints the URL. The limit is 20 minutes (`DEPLOY_TIMEOUT_SECONDS`).

The upload is asynchronous on purpose. A synchronous `az webapp deploy` keeps one HTTP
request open for the whole remote build, and the App Service front end can end it with
**504 GatewayTimeout** while the build carries on and succeeds (see
[troubleshooting](#6-logs-and-troubleshooting)).

On the first deployment the app can fail to start for a few minutes: at startup it
checks that the archive container exists and is private, which needs the new role
assignment to propagate. App Service restarts the app and the script keeps waiting.

## 2a. Deploy from Azure Cloud Shell (no local tools)

[Azure Cloud Shell](https://shell.azure.com) already has the Azure CLI, Bicep, Git,
the GitHub CLI, `curl` and Python, and you are signed in. Choose **Bash**.

**Option A: provision and deploy from the public repository**

```bash
az account set --subscription "<subscription name or id>"
git clone https://github.com/azurekid/AgentTrap.git
cd AgentTrap

infra/deploy.sh --what-if     # preview
infra/deploy.sh               # provision + deploy, prints the site URL
```

`RESOURCE_GROUP` and `LOCATION` work as above, e.g.
`RESOURCE_GROUP=rg-skillvenom-test infra/deploy.sh`. To deploy a later version, run
`git pull` and then `infra/deploy.sh --code-only`.

**Option B: upload a ZIP to an existing web app**

Use this when the infrastructure already exists and you have a package built locally
with `infra/package.sh` (`dist/skillvenom.zip`), for example with unpushed changes.

1. In Cloud Shell select **Manage files → Upload** and choose `skillvenom.zip`.
   It is stored in your home directory (`~/skillvenom.zip`).
2. Deploy it:

```bash
RG=rg-skillvenom
APP=$(az webapp list -g $RG --query "[?tags.application=='SkillVenom'].name | [0]" -o tsv)
az webapp deploy -g $RG -n $APP --src-path ~/skillvenom.zip --type zip --async true
az webapp log deployment list -g $RG -n $APP --query "[0].{status:status, complete:complete}"   # 4 + true = done
curl -s "https://$(az webapp show -g $RG -n $APP --query defaultHostName -o tsv)/healthz"
```

`--async true` returns as soon as the upload is accepted; repeat the status command
until `status` is `4` (`3` means the build failed). With a clone of the repository,
`infra/deploy-code.sh $RG $APP ~/skillvenom.zip` does the waiting for you.

Notes:

- The account you use in Cloud Shell needs the same rights as in
  [Prerequisites](#1-prerequisites) (*Owner*, or *Contributor* plus *User Access Administrator*).
- Cloud Shell disconnects after 20 minutes without interaction. `deploy.sh` normally
  finishes well within that; if the session drops, run `infra/deploy.sh --code-only`
  (or check `/healthz`), because the infrastructure deployment continues in Azure.
- With an **ephemeral session** (no storage account), the clone and uploaded files are
  removed when the session ends. Nothing in Azure depends on them.
- `infra/setup-github-oidc.sh` also runs in Cloud Shell after `gh auth login`.

## 3. Continuous deployment with GitHub Actions

Run once, after the first deployment:

```bash
RESOURCE_GROUP=rg-skillvenom infra/setup-github-oidc.sh azurekid/AgentTrap
```

The script:

- creates (or reuses) the Entra app `github-<owner>-<repo>-deploy` and its service principal;
- adds a federated credential for `repo:<owner>/<repo>:environment:production`, so only
  jobs in the `production` environment of that repository can sign in, without a secret;
- grants *Website Contributor* on the web app only;
- creates the `production` GitHub environment;
- sets repository variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
  `AZURE_RESOURCE_GROUP` and `AZURE_WEBAPP_NAME` (identifiers, not secrets).

Add required reviewers to the `production` environment in the repository settings if
releases should be approved.

The workflow runs on pushes to `main` that change `web/**`, `scan_agents_md.py`,
`credential_rules.json`, `SOURCES.md`, `requirements.txt`, `infra/package.sh`,
`infra/deploy-code.sh` or the
workflow itself, and on manual **Run workflow**:

1. **test**: Python 3.14 test suite, PowerShell/Python parity tests and `node --check`
   for the browser scripts.
2. **deploy** (skipped until `AZURE_CLIENT_ID` is set): package, OIDC sign-in,
   then `infra/deploy-code.sh`, which uploads asynchronously, waits for the remote build
   and checks that `/healthz` is OK and `/` contains the scanner.

CI deploys code only. Changes to `infra/` are applied by running `infra/deploy.sh`,
so the pipeline never holds rights to create role assignments.

## 4. Updating

| Change | How |
| --- | --- |
| Application code | Push to `main` (GitHub Actions), or `infra/deploy.sh --code-only` |
| Infrastructure or parameters | Edit `infra/`, run `infra/deploy.sh --what-if`, then `infra/deploy.sh` |
| Python runtime | Change `pythonVersion`, run the tests on that version, then `infra/deploy.sh` |

Redeploying the template is idempotent: names are derived from the resource group, so
existing resources are updated, not duplicated.

## 5. Verify

- `https://<app>/healthz` returns `{"status":"ok"}`; `/` shows the scanner, and
  `/coverage`, `/samples` and `/sources` load.
- Upload `tests/benign/AGENTS.md`: no high-risk findings, no archive record.
- Run `python tools/fixtures.py /tmp/skillvenom-fixtures` and upload
  `/tmp/skillvenom-fixtures/tests/repo/.codex/config.toml`: `CODEX-FULL-ACCESS` and a
  private record under `investigations/`. Repeat with the consent box unticked: the
  report says *opted out* and no blob is written.
- Scan a small public GitHub repository; the report shows the pinned commit.
- Download the JSON report; credential-shaped values are redacted.
- Infrastructure checks:

```bash
RG=rg-skillvenom
ST=$(az storage account list -g $RG --query "[0].name" -o tsv)
az storage account show -n $ST --query "{sharedKey:allowSharedKeyAccess, publicBlob:allowBlobPublicAccess}"
az storage account management-policy show -g $RG --account-name $ST --query "policy.rules[].name"
az webapp config appsettings list -g $RG -n <app> --query "[].name"   # no keys or secrets
```

## 6. Logs and troubleshooting

Application output (Uvicorn and scan IDs, never uploaded content) goes to the
`AppServiceConsoleLogs` table; archive access is in `StorageBlobLogs`:

```kusto
AppServiceConsoleLogs | where TimeGenerated > ago(1h) | project TimeGenerated, ResultDescription
StorageBlobLogs | where TimeGenerated > ago(1d) | project TimeGenerated, OperationName, StatusCode, AuthenticationType, CallerIpAddress
```

Live tail: `az webapp log config -g <rg> -n <app> --docker-container-logging filesystem`,
then `az webapp log tail -g <rg> -n <app>`.

| Symptom | Cause and fix |
| --- | --- |
| Startup error `AuthorizationPermissionMismatch` / 403 on the container | Role assignment still propagating; wait a few minutes. If it persists, check the *Storage Blob Data Contributor* assignment on the container. |
| `Configure the 30-day Blob lifecycle policy…` | `AZURE_ARCHIVE_RETENTION_CONFIRMED` missing; redeploy the template. |
| `az webapp deploy` fails with **HTTP 504 GatewayTimeout** (`Deployment failed … 504.0 GatewayTimeout`) | Usually not a failure: the synchronous request timed out while the remote build continued. Check `az webapp log deployment list -g <rg> -n <app> --query "[0].{status:status, complete:complete}"` (`4` = succeeded, `1`/`2` = still building, `3` = failed) and `/healthz`. Use `--async true` or `infra/deploy-code.sh` to avoid it. Do not start another deployment while one is building. |
| `ModuleNotFoundError` | Remote build did not run; check `SCM_DO_BUILD_DURING_DEPLOYMENT=true` and redeploy the code. |
| `AuthorizationFailed` on `Microsoft.Authorization/roleAssignments/write` during `deploy.sh` | Your account lacks *User Access Administrator*/*Owner* on the resource group. |
| GitHub deploy job skipped | `infra/setup-github-oidc.sh` has not been run (no `AZURE_CLIENT_ID` variable). |
| `AADSTS700213` / no matching federated identity | The job did not run in the `production` environment, or the repository was renamed; rerun the setup script. |
| Scans return 429 | Per-client (10/10 min) or per-instance (60/10 min) limits; expected under load. |
| GitHub scans fail with rate-limit errors | GitHub's unauthenticated API quota for the App Service outbound IP; users can upload files instead. |

## 7. Public-service hardening

App Service is exposed directly over HTTPS. The application enforces request-size
limits, per-client and per-instance scan limits, two concurrent scans and isolated
scanner timeouts. These are single-process safety controls, not DDoS protection.
Keep one worker and one instance: limits are held in memory per process.

For higher exposure, add Azure Front Door Premium with WAF (managed rules, rate
limiting, bot protection), restrict App Service access to the `AzureFrontDoor.Backend`
service tag with an `X-Azure-FDID` check, and set `trustedProxyHops` to `2`.
Private endpoints and VNet integration are not part of this template; add them if
storage must be unreachable from the internet. Shared-key access is already disabled,
so Microsoft Entra ID RBAC is the only data path.

Investigators need their own *Storage Blob Data Reader* assignment on the container;
there is no public archive API. Review the legal basis for retention, the pre-ticked
consent default, the deletion workflow and access audits before going live. Keep
HTTP/APM body logging disabled; exported reports and file names may still be sensitive.

## 8. Remove the deployment

```bash
az group delete --name rg-skillvenom --yes
az ad app delete --id "$(az ad app list --display-name github-azurekid-AgentTrap-deploy --query '[0].appId' -o tsv)"
```

Deleting the resource group removes the archive, statistics and logs immediately.
Remove the `AZURE_*` repository variables and the `production` environment in GitHub
if the workflow should stop trying to deploy.
