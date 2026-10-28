# AgentLens

A cybersecurity dashboard and static scanner for the files that guide AI agents.
Inspect uploaded files or a public GitHub repository for prompt injection, hidden
instructions, unsafe commands, agent permission changes, credential theft patterns,
and potentially embedded secrets.

AgentLens is the defensive inspection platform, previously branded SkillVenom
and originally AgentTrap. The GitHub repository remains `azurekid/AgentTrap`.
The separate
[SkillVenom research repository](https://github.com/azurekid/SkillVenom) holds the
red-team research and malicious-skill use cases used to test this scanner.
AgentLens inspects the evidence; SkillVenom supplies research and samples.

Existing Azure resource names, tags, storage container names, browser session keys
and SARIF fingerprint keys retain their legacy identifiers for compatibility.
The rebrand does not rename deployed resources, move stored data or change scan rules.

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
These activity totals are separate from the optional uniqueness registry described
below; they must not be presented as a count of distinct skills.

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
listings carry no file sizes, so the 500 files / 256 KiB / 5 MiB limits are enforced while reading files.

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
(the 11 tactics observable in static agent files, in ATLAS matrix order) and each
hit technique with its ATLAS mitigations. The results page draws this as a radar
("spiderweb") chart with technique and mitigation cards. Where ATLAS lists no
mitigation for a technique, the card shows clearly labelled **AgentLens guidance**.

The rule-to-technique mapping in [web/atlas.json](web/atlas.json) is analyst
judgement; names, tactics, URLs, and mitigations come from the official ATLAS STIX
release. To refresh it from a newer release:

```bash
curl -LO https://github.com/mitre-atlas/atlas-data/releases/download/v2026.09/stix-atlas.json
python tools/build_atlas_mapping.py stix-atlas.json
```

The generator validates every rule's technique/tactic pairing; a test fails if a
detector has no mapping.

### Evidence-based skill evaluation

Reports include an `evaluation` and a `provenance` object in both API responses and
downloaded JSON. The report UI groups evidence into seven review categories:
instruction control, credentials, data egress, execution/persistence, permissions,
obfuscation, and supply chain/destinations. Each category includes review guidance.
Search findings by file, rule or text and combine category and severity filters.

The **signal risk score** is not a trust score or probability of malware. Method
`signal-risk-v1` adds the highest severity weight for each distinct matched rule
across all inspected files: CRITICAL 40, HIGH 20, MEDIUM 5, LOW 1, capped at 100.
Repeating a match does not increase its rule's contribution. Any finding needs
review, including a low score. A complete scan with no findings scores zero, which
is not approval. Partial scans and scans with no target files have a null score.
Compare scores only with the same method, detector fingerprint and scan scope.
Changing detector files requires a process restart, as with the existing scanner.

`GET /api/methodology` publishes the scoring formula, detector SHA256, rule/category
assignments and performed/not-performed checks. The public
[`/coverage#methodology`](web/static/coverage.html) section explains the same limits.
There is **no** sandbox execution, publisher reputation verification, skill-signature
verification, live credential validation or installed-dependency analysis.
Static config checks do not evaluate the behavior of a running MCP server.

Each report records a deterministic, path-sorted manifest with file lengths and
SHA256 hashes of the **inspected text re-encoded as UTF-8 after optional BOM removal**.
These are not raw-download hashes. The manifest hash identifies that list; the
detector fingerprint hashes the scanner, credential rules, domain allowlist, ATLAS
mapping, evaluation, structured MCP inspection, artifact identity, scan-worker and
repository-selection implementations. These fingerprints are not signed
attestations, and a report copied or edited outside the service is not independently
authenticated. Repository reports retain the existing pinned commit identity.

No uploaded report or skill is automatically published in a searchable public
directory. Existing retention consent, private-token handling and redaction remain
unchanged. A public directory, reputation service or verified badge requires
separate publication consent, identity checks, expiry/rescanning and moderation.

### Structured MCP inspection

The web scanner inspects saved JSON tool-definition arrays in `tools` or a JSON-RPC
`result.tools` response. It parses JSON and applies the existing detectors to decoded
tool metadata, including schema descriptions and nested strings. Escaped instructions
are therefore inspected as text, not just as serialized escape sequences. Findings
carry `evidence_source: decoded_json` and an RFC 6901 `json_pointer`; `line: 0`
means there is no claimed physical source-line mapping for the decoded value.
The report displays the pointer instead, including in the false-positive dialog.
Submitted feedback includes that pointer (bounded to 8,192 characters) as location
metadata; snippets remain opt-in. This addition is in the isolated web scan
worker, not the standalone Python/PowerShell scanners.

Schema-shape inconsistencies, duplicate names and sensitive-input names are separate
`mcp.observations`: they do not increase severity counts or the signal score. A password
parameter, an ordinary string without a regex, or a tool's legitimate description is
not automatically a vulnerability. This is not a full JSON Schema validator.
`format: password` does not enforce redaction or prevent logging.

Inspection is bounded to 500 tool entries, 4,000 traversed nodes and depth 32 per
document. A continuation cursor or exceeded limit produces an explicit incomplete
scan with no score. Strict-JSON parse failures disclose `not_parsed`; raw-text rules
still run. No server is contacted, no tool is invoked, and MCP runtime capabilities
are not inferred from arbitrary manifest permission fields.

### Encoded-text inspection

The web worker also applies existing rules to printable text decoded from base64
(including URL-safe base64 and PowerShell-style UTF-16LE), hex, `\xNN` escapes and
percent-encoded tokens. It follows mixed/nested encodings up to three layers.
Transformations operate on data only: no shell, JavaScript evaluation, decompression,
network calls or payload execution. Decoding alone does not add a new finding; the
existing raw-text blob heuristics remain, while decoded output must match another
existing rule. Benign encoded text and rejected binary candidates do not receive
new vulnerability classifications.

Each derived finding includes `encoding_chain`, `decoded_line`, `encoded_offset`
and `evidence_source: decoded_payload`. Its physical `line` is the containing outer
encoded token's line, not a fictional line in a decoded source file. Within MCP
values it uses `line: 0` and the JSON pointer instead; offsets there are relative to
that decoded JSON string. Finding IDs include this evidence location. The UI shows
the transformation chain and distinguishes decoded evidence from source text.
Any detected secret masks all companion snippets in the containing file.

Budgets are shared by raw text and MCP values in each file: 128 candidate attempts,
32 decoded payloads and 64 KiB of decoded UTF-8 text. Exhausting a budget or finding
a further valid layer beyond the depth limit marks inspection **partial and unscored**.
The report's per-file `decoding` object discloses status, counts and limits reached.
These are supported-format checks, not a claim to decode every obfuscation technique.
The isolated process timeout and 2,000-finding request limit still apply. The
standalone Python/PowerShell scanners retain their existing behavior.

### SARIF export

The report's **Export SARIF** button creates SARIF 2.1.0 locally in the browser,
without resubmitting files or storing an extra server-side report. The output is
suitable for SARIF-consuming CI/code-scanning tools, subject to their own ingestion
requirements. It includes rule IDs, severity levels, relative URI-encoded file paths,
MITRE ATLAS/OWASP mappings, detector identity and stable finding fingerprints.
It does not invent CVSS scores or silently mark partial/no-target inspections as
successful clean scans.

Physical lines are emitted only when actually known. Decoded JSON findings use
logical JSON-pointer locations and no fabricated `startLine: 0` or `startLine: 1`.
Encoded-text chains remain result metadata. All snippets and original contents are
excluded from SARIF; file paths, pointers, rule messages and digests can still be
sensitive, so review an export before publishing it.

### Content identities and honest uniqueness counts

The report's **Snapshot review** section puts snapshots with CRITICAL/HIGH signals
first, with per-snapshot occurrence counts, completeness notes and full, copyable
content/evaluation fingerprints. Other agent files and MCP snapshots are labeled
separately rather than counted as skills. "View file findings" opens the relevant
file evidence after clearing report filters. Snapshots without high-risk signals
still receive fingerprints, not an approval badge. This is part of the current
browser-tab report, not an account dashboard or additional saved-report service.

Every report now includes `artifacts` and an `inventory`. A skill snapshot is the
inspected files under a folder containing `SKILL.md`, not one skill per uploaded
file. Nested skills are assigned their own files rather than double counted as a
complete parent package. Other files are classified separately; saved MCP tool
definitions outside skill packages count as MCP snapshots, not skills.

`artifact-v1` hashes a deterministic manifest of package-relative paths, SHA256
content hashes, lengths and file modes where known. Repository URLs and outer
skill-folder names do not participate. Copies of the same snapshot with the same
available metadata have the same content ID. Actual downloads/uploads also carry
**raw-byte hashes** for artifact identity, unlike the existing normalized inspected-text
hashes in `provenance`. BOM and line-ending changes therefore change the raw identity.
Unknown file modes are explicit; snapshots with unknown versus known executable
metadata are different identities, not silently equated.

An evaluation ID binds content to the detector fingerprint, scan options and
completeness. Finding IDs bind that evaluation to relative path, rule, physical line
or JSON pointer, evidence source and occurrence ordinal. They do not use raw secrets
or snippets as their identity input. Repeated scans deduplicate; a new detector build
creates new evaluations/findings but does not inflate distinct content counts.
Editing a byte creates a new content version: these are **not counts of distinct
people, publishers, logical skill names or safe skills**, and are not an adoption metric.

Only a pinned GitHub tree with every listed package file supported and inspected,
known file modes, no truncated listing, no uninspected simple `scripts/`, `references/`
or `assets/` references, and no partial scan can claim a complete supported package.
Uploads, GitLab and Azure DevOps packages conservatively remain snapshots because
this implementation does not prove complete uploaded contents or equivalent mode
metadata there. Unsupported files, links and submodules inside a skill prevent a
complete-package claim. Reference accounting is a bounded static check for those
relative paths, not a general dependency resolver. Nothing here proves that remote
dependencies, referenced websites or runtime behavior are safe.

`GET /api/statistics/unique` exposes exact deduplicated counts for opted-in
`skill_snapshots`, `complete_skill_versions`, `mcp_snapshots`, `agent_files`,
`evaluations` and `findings`, plus `since` and `as_of`. The existing
`GET /api/statistics` still reports repeat-inclusive activity. Historical uniqueness
is not inferred; `since` is null until the first registry entry.

The separate **Contribute to unique evaluation counts** checkbox is **off by default**.
API callers opt in with `uniqueness_consent: true` (repository JSON) or
`uniqueness_consent=true` (multipart upload). This is independent of 30-day original-file
retention. Private-token scans are excluded even if consent is requested. The
uniqueness registry retains digest identities indefinitely, with no names, URLs,
snippets, secret values or originals. Hashes can still identify known content, so
do not opt in for confidential or low-entropy material. No reports are auto-published.

Storage uses 16 bounded digest-set shards under `uniqueness-v1/`, outside the
investigation lifecycle prefix. Local storage uses process locking, mode-0600 atomic
files and the existing single-process deployment model. Azure uses the existing
private container/managed identity and conditional ETag writes, with idempotent
conflict retries. Each shard is capped at 2 MiB (32 MiB total serialized records).
This is bounded exact tracking, not an unlimited registry; capacity/corruption/storage
errors are explicit and never silently reset or approximate counts. Migrate to a
transactional database before larger-scale registry use.

Counts are a cross-shard snapshot, cached up to 60 seconds; concurrent writes are not
a global transaction. A failed submission may have recorded some digests, disclosed
in the response, and retries do not duplicate them. Registry failure does not hide
scan results. Public counters are aggregates only; there is no public digest lookup.

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
Actions, MCP, any-agent). Each case folder carries a `use-case.json`, a complete
defanged payload under its real name (`payload/AGENTS.md`, `payload/.claude/settings.json`, ...),
an optional benign look-alike, and a generated `README.md`;
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

### Trusted domains

Links to hosts not on the allowlist raise a LOW `UNLISTED-DOMAIN` finding. The list lives in
[allowlist.json](allowlist.json) (`{"domains": [...]}`; a host matches an entry or any
subdomain of it) and is read by both `scan_agents_md.py` and `Scan-AgentsMd.ps1`, so edit
that one file to trust another domain. The Python CLI also accepts `--allow DOMAIN` and the
PowerShell script `-Allow` for one-off additions. The web app uses the file as shipped.

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

- 500 files, 256 KiB/file, 5 MiB combined text, 8,192 characters/line, UTF-8 only.
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
(`SKILL-TRIGGER-HIJACK`). The web platform now adds the explicitly limited signal
score and SARIF export documented above. LLM semantic review, malware/trust verdicts
and a signed coverage ledger are not implemented. The older
`tests/repo`, `samples/`, `tests/atlas_cases` and `tests/rule_samples.json` fixtures are
kept as internal regression guards and are not part of the user-facing catalogue.

The [SkillsGuard engine](https://github.com/Teycir/SkillsGuard/tree/7badb5157f8f9e4dd9ee2acb6e0129636e3147e3/src)
was also reviewed, including scanning, recursive decoding, SARIF, baseline/diff
handling and PowerShell/container rules. Its package declares MIT licensing.
Bounded recursive decoding and SARIF interoperability were independently implemented
here as useful design ideas; its code was not copied and it is not a dependency.
We did not adopt submitter-controlled suppression comments, blanket comment/test
skipping, or the assumption that ordinary downloads, credential APIs or container
root users prove malicious behavior. CLI baselines, git-diff scanning, watch mode,
hook installation and additional language/container detectors remain separate work,
not features silently claimed by this addition.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests/
pwsh -NoProfile -File tests/Test-Scanner.ps1
for f in web/static/*.js; do node --check "$f"; done
node --test tests/test_sarif.cjs
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
