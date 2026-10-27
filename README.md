# AgentTrap

A cybersecurity dashboard and static scanner for the files that guide AI agents.
Inspect uploaded files or a public GitHub repository for prompt injection, hidden
instructions, unsafe commands, agent permission changes, credential theft patterns,
and potentially embedded secrets.

## Run locally

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn web.app:app --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers
```

Open http://127.0.0.1:8000. No frontend build, database, or API key is required.
Uploads and repository contents are **never executed or rendered as Markdown**.
Findings are text-only, and reports are downloadable as JSON.
The responsive inspection workspace uses restrained motion for scan activity and
respects the system's reduced-motion preference.
Site-wide files-scanned and security-finding counters persist across restarts.
They count each completed inspection's actual scanned files (including inspected
files in partial reports); repeats count again. Findings are heuristic signals,
not confirmed vulnerabilities. Totals start at zero when this feature is enabled;
older investigations are not backfilled. Only aggregate counts are stored, with
no filenames, repository URLs, credentials, or content. Locally these live in
`ARCHIVE_DIRECTORY/statistics/totals.json` (atomic replace, single process); Azure uses
an ETag-guarded JSON blob, `statistics/totals.json`, in
the private archive container, outside the investigation retention prefix.

### Supported files

- AGENTS.md, AGENT.md, CLAUDE.md, GEMINI.md, SKILL.md, Copilot instructions,
  `*.instructions.md`, `*.agent.md`, `*.prompt.md`, `*.chatmode.md`, and editor rules.
- Claude settings/hooks, Codex TOML, Gemini settings, Cursor MCP/rules, MCP JSON,
  VS Code settings/tasks/MCP, and the other paths supported by the existing scanner.
- GitHub Actions workflows are **opt-in** for repository scans; the toggle is shown
  only on the GitHub tab, and folder uploads skip `.github/workflows`.
- Individual uploads may also be arbitrary Markdown, JSON, or TOML files.
  Folder uploads use agent-aware discovery, not all Markdown/config files.
  Retain parent paths (for example `.claude/settings.json`) using **Select folder**.

Repository URLs must be `https://github.com/owner/repository` (optionally `.git`).
Only public repositories and their default branch are supported. A scan is pinned
to a commit SHA; no credentials, arbitrary hosts, branch URLs, redirects, submodules,
or git hooks are accepted. Ordinary README files are not repository scan targets.
Links to agent files are skipped and reported as a partial scan.

### MITRE ATLAS mapping

Each finding carries the [MITRE ATLAS](https://atlas.mitre.org/) technique IDs its
rule maps to, and every report includes an `atlas` summary: findings per tactic
(the 10 tactics observable in static agent files, in ATLAS matrix order) and each
hit technique with its ATLAS mitigations. The results page draws this as a radar
("spiderweb") chart with technique and mitigation cards. Where ATLAS lists no
mitigation for a technique, the card shows clearly labelled **AgentTrap guidance**.

The rule-to-technique mapping in [web/atlas.json](web/atlas.json) is analyst
judgement; names, tactics, URLs, and mitigations come from the official ATLAS STIX
release. To refresh it from a newer release:

```bash
curl -LO https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/stix-atlas.json
python tools/build_atlas_mapping.py stix-atlas.json
```

The generator validates every rule's technique/tactic pairing; a test fails if a
detector has no mapping.

### Research sources

`/sources` renders [SOURCES.md](SOURCES.md) as a searchable, filterable page in the
site style (`/api/sources` returns the parsed tables). Finding references link to
`/sources#source-N`.

### Secrets and credentials

Both CLI scanners load [credential_rules.json](credential_rules.json). New
heuristics detect GitHub/npm/Slack/AI-provider tokens, AWS access-key IDs, Google
API keys, JWT-like strings, private-key headers, service URLs with passwords,
literal authentication headers, and hard-coded secret assignments (including
Azure connection-string account keys and SAS signatures).

Findings on credential-bearing lines are redacted; private-key files have all
finding snippets redacted. These are **potential** credentials, not provider-verified
live secrets. Common environment references and obvious placeholders are excluded.
Format detection cannot catch every secret, and synthetic examples can be flagged.
Do not treat report redaction as a general-purpose data-loss prevention service.
Real exposures require revocation/rotation and access-log review.

### Investigation archive and disclosure

The page displays a notice **before submission**. Files with HIGH or CRITICAL
findings are automatically retained for investigation without a consent checkbox,
as requested. Only those risky files are archived; clean files are not retained.
The archive contains original text (including any secrets), paths, hashes,
redacted findings, and source/commit metadata. It is not anonymized.
Scan reports remain in browser memory until a rescan, reload, or export.

- Development: `.archive/`, directories `0700`, files `0600`; ignored by Git.
- Local retention: prune at startup, before writes, and hourly while running.
  Expired files are removed at the next cleanup, not while the application is stopped.
- Local archive quota: 256 MiB by default; change `ARCHIVE_MAX_BYTES`.
- Azure: private Blob container and managed identity. Set a 30-day lifecycle policy
  before enabling it. Azure lifecycle deletion is asynchronous.
- No public archive list, read, download, or delete API exists. Authorized
  investigators use filesystem permissions or Azure RBAC.
- Archive failures are logged without content and explicitly shown in the report;
  they do not erase otherwise valid scan findings.

Operators must publish an appropriate privacy/legal notice, restrict investigator
access, account for storage backups/soft delete, and assess authorization and
retention obligations before publicly accepting submissions.

| Environment variable | Default / purpose |
|---|---|
| `ARCHIVE_BACKEND` | `local` or `azure` |
| `ARCHIVE_DIRECTORY` | `.archive/`, outside the public web routes |
| `ARCHIVE_MAX_BYTES` | `268435456`, local retained-payload quota |
| `AZURE_STORAGE_ACCOUNT` | Required for Azure mode |
| `AZURE_STORAGE_CONTAINER` | `agenttrap-investigations` |
| `AZURE_ARCHIVE_RETENTION_CONFIRMED` | Must be `true` for Azure mode, after lifecycle setup |

## Limits and public-service operation

- 100 files, 256 KiB/file, 2 MiB combined text, 8,192 characters/line, UTF-8 only.
- Requests are bounded to 3 MiB **before multipart parsing**.
- Two concurrent scan requests; 10 requests/client/10 minutes,
  60 requests/instance/10 minutes; 15-second isolated scanner timeout.
- GitHub retrieval never downloads the whole repository. It resolves the default
  branch to a commit, lists that commit's file tree (16 MiB listing cap), and
  fetches **only supported agent files** from `raw.githubusercontent.com`, pinned
  to the same commit and verified against the tree's git blob hash. File limits
  are checked from the tree before downloading. Fixed outbound hosts
  (`api.github.com`, `raw.githubusercontent.com`), bounded reads, a 40-second
  deadline, no environment proxy or redirects. A tree truncated by GitHub
  yields a partial report.
- Exceeding limits is an error, never a successful truncated scan.
- No targets and skipped links are distinct from a complete scan with no findings.

Use **one Uvicorn worker**. Limits are per process, not distributed. Forwarded
client headers are intentionally not trusted; behind a reverse proxy, clients
may share the proxy's bucket. Before public Azure exposure, put the service behind
Azure Front Door/WAF (or an equivalent controlled gateway), add shared edge rate
limits and body/time limits, prevent direct backend bypass, monitor spend, and
configure alerts. In-process controls are a safety net, not DDoS protection.
GitHub's unauthenticated API quota can be exhausted; upload files instead.
Never add a GitHub access token to this public retrieval adapter.

Static findings are not a security certification. Legitimate instructions can
trigger detections; missed threats are possible. See [SOURCES.md](SOURCES.md).

## Command-line scanners

```bash
python3 scan_agents_md.py --json tests/repo
python3 scan_agents_md.py --include-workflows --fail-on HIGH tests/repo
pwsh -NoProfile -File Scan-AgentsMd.ps1 -Path tests/repo -Json
```

Exit code 1 means findings meet the configured threshold. Discovery and existing
research-derived rules are preserved; embedded-secret detection is additive.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests/test_web.py
pwsh -NoProfile -File tests/Test-Scanner.ps1
node --check web/static/app.js && node --check web/static/fx.js
```

The parity test in the Python suite requires PowerShell (`pwsh`). Synthetic
credential fixtures are assembled at runtime; no real credentials are checked in.

## Deploy to Azure

See [Azure deployment instructions](docs/azure-deployment.md). No Azure resources
are provisioned by this repository or by running the local application.
