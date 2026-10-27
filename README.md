# SkillVenom

A cybersecurity dashboard and static scanner for the files that guide AI agents.
Inspect uploaded files or a public GitHub repository for prompt injection, hidden
instructions, unsafe commands, agent permission changes, credential theft patterns,
and potentially embedded secrets.

SkillVenom was previously named AgentTrap; the GitHub repository is still
`azurekid/AgentTrap`. The separate
[SkillVenom research repository](https://github.com/azurekid/SkillVenom) holds the
original malicious-skill use cases this scanner detects.

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

Supported repository URLs (default branch only, pinned to one commit SHA, `.git` suffix optional):

| Provider | URL | Private repositories |
|---|---|---|
| GitHub | `https://github.com/owner/repo` | fine-grained token, Contents: read-only |
| GitLab | `https://gitlab.com/group/[subgroup/]project` | token with `read_repository` |
| Azure DevOps | `https://dev.azure.com/org/project/_git/repo` | PAT with Code: Read |

Private repositories need an optional **access token**. It travels in the request body over
HTTPS, is sent only to the provider's API host in an auth header, is never logged, stored or
placed in a URL, and a scan that uses a token is **never archived**, whatever the consent
checkbox says. Use short-lived read-only tokens and revoke them afterwards. Every inspected
file is verified against the pinned commit's git object hash. Azure DevOps and GitLab
listings carry no file sizes, so the 100 files / 256 KiB / 2 MiB limits are enforced while reading files.

Self-managed servers are **operator-configured**: set `SCM_GITLAB_HOSTS` and/or
`SCM_AZDO_HOSTS` to comma-separated host names (for example `git.corp.example`). Users cannot
add hosts, ports or redirects, so the server cannot be pointed at arbitrary addresses. The
Azure DevOps Server URL form is `https://host/<collection>/<project>/_git/<repo>`.
The App Service must be able to reach those hosts (VNet integration for internal servers).
No credentials in the URL, branch URLs, redirects, submodules or git hooks are accepted.
The GitLab/Azure DevOps adapters are covered by mocked tests only; verify against a real
instance before relying on them. Ordinary README files are not repository scan targets.
Links to agent files are skipped and reported as a partial scan.

### MITRE ATLAS mapping

Each finding carries the [MITRE ATLAS](https://atlas.mitre.org/) technique IDs its
rule maps to, and every report includes an `atlas` summary: findings per tactic
(the 10 tactics observable in static agent files, in ATLAS matrix order) and each
hit technique with its ATLAS mitigations. The results page draws this as a radar
("spiderweb") chart with technique and mitigation cards. Where ATLAS lists no
mitigation for a technique, the card shows clearly labelled **SkillVenom guidance**.

The rule-to-technique mapping in [web/atlas.json](web/atlas.json) is analyst
judgement; names, tactics, URLs, and mitigations come from the official ATLAS STIX
release. To refresh it from a newer release:

```bash
curl -LO https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/stix-atlas.json
python tools/build_atlas_mapping.py stix-atlas.json
```

The generator validates every rule's technique/tactic pairing; a test fails if a
detector has no mapping.

### MITRE ATLAS case-study coverage

All 73 case studies in ATLAS v2026.09 are classified in
[tools/atlas_case_studies.json](tools/atlas_case_studies.json):

| Scope | Count | Meaning |
|---|---|---|
| `file` | 21 | Detected; a defanged payload per case study in [tests/atlas_cases/cases.json](tests/atlas_cases/cases.json) is regression-tested in Python and PowerShell |
| `partial` | 5 | A related artifact is detected (leaked keys, worm text, URLs in a model template) |
| `channel` | 12 | Injection delivered by web, email, chat, tickets or calendars; the payload is detected only if it lands in a scanned file |
| `out` | 35 | Model evasion, data poisoning, deepfakes, model files, exposed infrastructure, or non-agent malware |

The case studies added the `MEMORY-POISONING`, `FILE-EXFIL`, `REMOTE-COMMANDS`,
`CLICKFIX`, `OFFENSIVE-TASKING` and `AI-PREFILL-LINK` rules and extended
`WORM-PROPAGATION` and `WIPER-INSTRUCTION`.

### Keeping detection current

1. **Watch.** [.github/workflows/atlas-update-check.yml](.github/workflows/atlas-update-check.yml)
   runs [tools/check_atlas_updates.py](tools/check_atlas_updates.py) weekly. It opens
   (or comments on) one issue when a new ATLAS release appears, a case study is not yet
   classified, or a mapped technique is revoked, deprecated or removed. Run it locally
   with `python tools/check_atlas_updates.py`.
2. **Triage.** Classify each new case study in `tools/atlas_case_studies.json`. For a
   `file` case study, add a defanged payload with its expected rules to
   `tests/atlas_cases/cases.json`; the test fails until both files agree.
3. **Detect.** If the payload is missed, add or extend a rule in `scan_agents_md.py`,
   add `RULE_REFS`, and cite the case study in [SOURCES.md](SOURCES.md). Regenerate the
   PowerShell rule table from the Python source with
   `python tools/sync_powershell_rules.py` (the parity tests enforce identical findings;
   `--check` fails if `Scan-AgentsMd.ps1` is stale). Check new rules against benign agent
   files for false positives.
4. **Map.** Add the rule to `tools/build_atlas_mapping.py`, bump `VERSION`, and
   regenerate `web/atlas.json` from the new release.
5. **Sample.** Add the case to [use-cases/](use-cases) (validated by
   `python tools/use_cases.py validate`) and regenerate the public sample library with
   `python tools/build_sample_catalog.py` (a test fails while `web/samples.json` is stale).
6. **Verify.** Run the test suite and redeploy.

Beyond ATLAS, [.github/workflows/research-watch.yml](.github/workflows/research-watch.yml)
runs [tools/check_research_feeds.py](tools/check_research_feeds.py) weekly. It reads the
feeds in [tools/research_feeds.json](tools/research_feeds.json) (arXiv cs.CR, NVD CVEs,
Embrace The Red, Simon Willison's prompt-injection tag, BleepingComputer and a Google
News search), keeps items that mention an agent subject (AGENTS.md, MCP, Claude Code,
Copilot, …) and a risk term, drops anything already cited in `SOURCES.md`, and opens a
dated triage issue with a checklist. Run it locally with
`python tools/check_research_feeds.py --days 30`. Each relevant item follows the same
loop: cite it in `SOURCES.md`, add a defanged sample to `tests/rule_samples.json` (or an
ATLAS case), then add or extend a rule. Feed text is untrusted: the report strips
markup and links from titles, and should be triaged by a person, not handed to an agent
with tool access. Tune noisy terms in the JSON config.

### OWASP Agentic (ASI) mapping

Alongside MITRE ATLAS, every finding is also mapped to the
[OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/#agenticsecurity)
threat taxonomy (for example `ASI01 Agent Goal Hijack`). Findings carry a teal OWASP
chip next to the purple ATLAS chips, and the report includes an `owasp_asi` summary of
risks and the findings per risk. The mapping lives in
[tools/build_atlas_mapping.py](tools/build_atlas_mapping.py) and is regenerated into
`web/atlas.json` with the ATLAS build.

### Use-case catalogue and threat sample library

The [use-cases/](use-cases) directory is a test-backed catalogue of defanged
agent-file attacks, organised into nine categories (prompt injection, data
exfiltration, command execution, obfuscation, autonomy abuse, supply chain,
memory/persistence, tool misuse, credentials) and tagged by target platform (Claude
Code, GitHub Copilot, Cursor, Codex, Gemini CLI, VS Code, Windsurf, Cline, GitHub
Actions, MCP, any-agent). Each case folder carries a `use-case.json`, an inert
`payload/<ID>.inert`, an optional benign look-alike, and a generated `README.md`;
[use-cases/CATALOG.md](use-cases/CATALOG.md) is the generated index.

- [use-cases/taxonomy.json](use-cases/taxonomy.json) and
  [use-cases/schema.json](use-cases/schema.json) define categories, platforms and the
  per-case schema.
- [tools/use_cases.py](tools/use_cases.py) validates the catalogue, renders the
  `README.md`/`CATALOG.md` files (`render --check` in tests), and can `materialize` a
  case to a scratch directory. Validation asserts each payload is discoverable by the
  web scanner and triggers its expected rules, and that each benign look-alike is clean.
- [tools/build_sample_catalog.py](tools/build_sample_catalog.py) turns the catalogue
  (plus synthetic secrets) into `web/samples.json`; a test fails while it is stale.

The **Samples** page (`/samples`) renders this catalogue grouped by category and
filterable by text, severity, category and platform. Each card shows the defanged
payload, the rules it triggers with file/line, its ATLAS and OWASP chips, why it works,
mitigations, and a link back to the source case. It is served from `web/samples.json`
(`/api/samples`); snippets are the scanner's redacted output, and synthetic credential
values are never published.

### Site pages

| Path | Content |
| --- | --- |
| `/` | Landing page with the scanner (upload or GitHub repository, consent, results), live statistics, how it works, links to each page. `?mode=repo` opens the repository tab |
| `/scan` | Redirects to `/#scanner` (keeps `?mode=repo`) |
| `/coverage` | Threat classes, ecosystems and file types inspected |
| `/samples` | Use-case catalogue |
| `/sources` | Research sources |

Old single-page anchors `/#coverage` and `/#samples` redirect to their pages. Every page shares the navigation and the footer credit to
[azurekid](https://github.com/azurekid).

### Research sources

`/sources` renders [SOURCES.md](SOURCES.md) as a searchable, filterable page in the
site style (`/api/sources` returns the parsed tables). Each finding's research
references link directly to the source article; `/sources#source-N` is the fallback
when a source has no URL.

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

The scanner page displays a notice **before submission** and an *Allow investigation
retention* checkbox that is **checked by default**. Users may uncheck it to opt out:
the scan still runs, nothing is archived, and the report shows
`archive.status = "opted_out"` (form field / JSON property `archive_consent`).
With consent, only files with HIGH or CRITICAL findings are archived; clean files are
not retained. Anonymous statistics (file and finding counts, no names, content or
URLs) are always recorded. A pre-ticked box may not count as valid consent under
GDPR/ePrivacy (CJEU *Planet49*); review this with your privacy counsel before going live.
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
| `AZURE_STORAGE_CONTAINER` | `skillvenom-investigations` |
| `AZURE_ARCHIVE_RETENTION_CONFIRMED` | Must be `true` for Azure mode, after lifecycle setup |

## Limits and public-service operation

- 100 files, 256 KiB/file, 2 MiB combined text, 8,192 characters/line, UTF-8 only.
- Requests are bounded to 3 MiB **before multipart parsing**.
- Two concurrent scan requests; 10 requests/client/10 minutes,
  60 requests/instance/10 minutes; isolated scanner timeout (`SCAN_TIMEOUT_SECONDS`, default 45).
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
client headers are not trusted by default. Set `TRUSTED_PROXY_HOPS` to the number of
reverse proxies that append `X-Forwarded-For` (Azure App Service: `1`; with Front Door
in front: `2`); the limiter then keys on the entry that many hops from the right, which
clients cannot forge. Without it, clients behind a proxy share the proxy's bucket. Before public Azure exposure, put the service behind
Azure Front Door/WAF (or an equivalent controlled gateway), add shared edge rate
limits and body/time limits, prevent direct backend bypass, monitor spend, and
configure alerts. In-process controls are a safety net, not DDoS protection.
GitHub's unauthenticated API quota can be exhausted; upload files instead.
Never add a GitHub access token to this public retrieval adapter.

Static findings are not a security certification. Legitimate instructions can
trigger detections; missed threats are possible. See [SOURCES.md](SOURCES.md).

## Command-line scanners

Hostile fixtures in `tests/repo`, `samples` and `poc/Downloads` are stored under
inert names (`AGENTS.md.inert`, `dot-claude/settings.json.inert`) so coding agents
working in this repository never auto-load them. Restore the real names in a
scratch directory outside the repository before scanning them:

```bash
python3 tools/fixtures.py /tmp/skillvenom-fixtures
python3 scan_agents_md.py --json /tmp/skillvenom-fixtures/tests/repo
python3 scan_agents_md.py --include-workflows --fail-on HIGH /tmp/skillvenom-fixtures/tests/repo
pwsh -NoProfile -File Scan-AgentsMd.ps1 -Path /tmp/skillvenom-fixtures/tests/repo -Json
```

Exit code 1 means findings meet the configured threshold. Discovery and existing
research-derived rules are preserved; embedded-secret detection is additive.

The `Rules` and `RuleRefs` tables in `Scan-AgentsMd.ps1` are **generated** from
`scan_agents_md.py` by `python tools/sync_powershell_rules.py`; edit the Python source,
not the generated blocks.

### External research adopted

Detectors and catalogue ideas were drawn from public agent-security research and
attributed in [SOURCES.md](SOURCES.md). Adopted: the category/platform catalogue layout of the
[SkillVenom research use-cases](https://github.com/azurekid/SkillVenom/tree/main/use-cases) and three missed payloads; Cisco skill-scanner's tool-shadowing idea
(`TOOL-SHADOWING`); and NVIDIA SkillSpector's broad-trigger idea
(`SKILL-TRIGGER-HIJACK`). Not adopted (by design or as future work): a numeric risk
score or verdict, LLM semantic review, and a SARIF/coverage-ledger output. The older
`tests/repo`, `samples/`, `tests/atlas_cases` and `tests/rule_samples.json` fixtures are
kept as internal regression guards and are not part of the user-facing catalogue.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests/test_web.py
pwsh -NoProfile -File tests/Test-Scanner.ps1
node --check web/static/app.js && node --check web/static/fx.js
```

The parity test in the Python suite requires PowerShell (`pwsh`). Synthetic
credential fixtures are assembled at runtime; no real credentials are checked in.
Both suites restore the inert fixtures in a temporary directory and fail if a
fixture is ever committed under an agent-loaded name.

## Deploy to Azure

Infrastructure as code is in [infra/](infra/): a Bicep template for Linux App Service
(B1, Python 3.14), a private keyless Storage account with the 30-day lifecycle rule,
managed-identity RBAC and Log Analytics, plus `infra/deploy.sh` and a GitHub Actions
workflow using OIDC. See [Azure deployment](docs/azure-deployment.md). Nothing is
provisioned until you run the script.
