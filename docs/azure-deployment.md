# Azure deployment guide

This is a manual deployment guide, not an executed deployment. Review resource
names, region, pricing, RBAC, and privacy obligations before provisioning.

## Architecture

Use Linux Azure App Service with a supported Python 3.11+ runtime and one Uvicorn
worker. The same application serves the dashboard and API. Store investigation
records in a private Azure Blob container; authenticate using the App Service's
system-assigned managed identity. No connection string, storage key, GitHub token,
database, or language-model service is needed.

For a public service, front App Service with Azure Front Door/WAF. Restrict App
Service ingress to your gateway, enforce HTTPS, configure a request size limit,
rate limits, bot controls and alerts, and disable caching for scan APIs.
Do not trust arbitrary forwarded client IP headers. The application's own limits
are single-process safety controls, not a distributed abuse-prevention service.

## 1. Prepare resources

In your chosen subscription/resource group, provision:

1. A Linux App Service plan and Python web app. Use a tier supporting your
   required uptime and gateway restrictions.
2. A Standard GPv2 Storage account with secure transfer required, TLS 1.2+,
   anonymous blob access disabled, and shared-key access disabled.
3. A private container named `agenttrap-investigations`.
4. A system-assigned managed identity on the web app.
5. A **Storage Blob Data Contributor** assignment for that identity scoped to
   this container, not the entire subscription. Investigators should receive
   only the roles needed for their work.

Use private endpoints/VNet integration if your requirements call for network
isolation, with DNS configured so App Service can reach Blob Storage.
Do not expose archive blobs through static website hosting, SAS links, or UI routes.

## 2. Configure mandatory retention

Add a Blob lifecycle management rule on the storage account:

- Enabled, block blobs.
- Prefix: `agenttrap-investigations/investigations/`.
- Delete base blobs **30 days after last modification**.
- Archive records use unique names and are never overwritten.

Review soft delete, snapshots, versioning, replication, backup, and legal-hold
settings: retained copies may otherwise outlive the stated retention period.
Lifecycle deletion is asynchronous, not an exact-to-the-second guarantee.

Example policy body for an operator's `az storage account management-policy create`
invocation (not an automatically applied infrastructure file):

```json
{
  "rules": [{
    "enabled": true,
    "name": "expire-agenttrap-investigations",
    "type": "Lifecycle",
    "definition": {
      "filters": {
        "blobTypes": ["blockBlob"],
        "prefixMatch": ["agenttrap-investigations/investigations/"]
      },
      "actions": {
        "baseBlob": {"delete": {"daysAfterModificationGreaterThan": 30}}
      }
    }
  }]
}
```

After confirming the applied policy, set these App Service application settings:

```text
ARCHIVE_BACKEND=azure
AZURE_STORAGE_ACCOUNT=<your-account-name>
AZURE_STORAGE_CONTAINER=agenttrap-investigations
AZURE_ARCHIVE_RETENTION_CONFIRMED=true
SCM_DO_BUILD_DURING_DEPLOYMENT=true
```

The retention confirmation is an operator attestation, not automatic lifecycle
verification. Startup rejects Azure mode without it and rejects containers with
public access. Storage-account-level prevention of anonymous access remains
an operator responsibility. Do not use the ephemeral App Service filesystem
for production investigation records.

## 3. Deploy application code

Deploy these application inputs from the repository root using your approved
App Service source/ZIP deployment pipeline:

```text
requirements.txt
scan_agents_md.py
credential_rules.json
SOURCES.md
web/
```

Do **not** package `.archive/`, `.env`, `.venv/`, local settings, test artifacts,
or the `poc/` directory. ZIP deployment must put the inputs at the archive root.
App Service's remote build installs `requirements.txt`.

Set the startup command:

```bash
python -m uvicorn web.app:app --host 0.0.0.0 --port 8000 --workers 1 --no-proxy-headers
```

Configure App Service Health Check to `/healthz`. Azure mode checks container
reachability and privacy at startup; health checks afterwards indicate application
liveness, not continuous storage availability. Archive write failures are returned
explicitly in scan reports and logged by scan ID without uploaded content.

Direct dependencies are pinned to the locally tested versions. For fully
reproducible releases, resolve and lock transitive dependencies in your delivery
pipeline as well.

## 4. Verify before opening public access

- `/healthz` returns `{"status":"ok"}` over HTTPS.
- Dashboard loads; upload `tests/benign/AGENTS.md`: no high-risk findings and no archive record.
- Upload `tests/repo/.codex/config.toml`: `CODEX-FULL-ACCESS`, private archive record,
  and visible retention notice. Use synthetic data for credential checks.
- Scan a small public GitHub repository; report the pinned commit, discovery,
  and any skipped targets. Empty repositories must report no targets, not certification.
- Download JSON and confirm credential-shaped values are redacted.
- Verify anonymous archive access is denied and no storage credentials are in app settings.
- Verify lifecycle and gateway limits, direct-backend restrictions, alerts and budgets.
- Keep HTTP/APM body logging disabled. Exported reports and filenames may still be sensitive.
- Review legal basis, permitted investigation use, deletion workflow, and access audits.

No Azure deployment, quota validation, pricing estimate, or live Blob integration
has been performed as part of generating this application. These remain deployment
operator checks.
