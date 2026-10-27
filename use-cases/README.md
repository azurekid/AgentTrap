# SkillVenom use-case catalogue

A catalogue of **defanged, test-backed** agent-file attacks, organised by category and tagged by
target platform. Each use case is one small payload plus the exact SkillVenom rules it should
trigger, a benign look-alike where one exists, and a mapping to MITRE ATLAS and OWASP Agentic
(ASI). It is the test-backed counterpart to catalogues such as the
[SkillVenom research use-cases](https://github.com/azurekid/SkillVenom/tree/main/use-cases) and
[skills-security-audit](https://github.com/agentnode-dev/skills-security-audit): every entry is a
working sample, not just prose.

See [CATALOG.md](CATALOG.md) for the full index (generated). Browse categories:

| Code | Category |
|------|----------|
| PI | Prompt Injection & Instruction Override |
| DE | Data Exfiltration & Covert Channels |
| CE | Command Execution & Remote Payloads |
| OB | Obfuscation & Hidden Content |
| PA | Autonomy & Platform-Config Abuse |
| SC | Supply Chain & Dependency Trust |
| MP | Memory, Persistence & Untrusted Sources |
| TM | Tool Misuse & Privilege Abuse |
| CR | Hardcoded Credentials & Secrets |

## Layout

```
use-cases/
  taxonomy.json           categories and platforms
  schema.json             JSON schema for every use-case.json
  _template/              starting point for a new case
  CATALOG.md              generated index (by category and by platform)
  <category-slug>/<ID>/
    use-case.json         metadata, expected rules, ATLAS/ASI mapping
    README.md             generated, human-readable
    payload/<ID>.inert    the defanged attack payload
    benign/<ID>.inert     optional clean look-alike that must NOT trigger HIGH/CRITICAL
```

## Safety rules

- **Every payload is inert and defanged.** Hosts use `.example`/`.invalid` domains or documented
  canaries; credentials are synthetic shapes, never live values. Never run a payload.
- Payloads are stored under `*.inert` filenames so coding agents working in this repo never
  auto-load them. The real path a scanner should treat the file as is recorded in
  `artifacts[].scan_as`.
- The scanners (`scan_agents_md.py` and `Scan-AgentsMd.ps1`) are the source of truth. `use-case.json`
  records the rules that **actually** fire, so the catalogue can never drift from the detectors.

## Tooling

```bash
python tools/use_cases.py validate        # schema + referential checks
python tools/use_cases.py render          # regenerate README.md files and CATALOG.md
python tools/use_cases.py render --check   # CI: fail if docs are stale
python tools/use_cases.py materialize DEST # copy payloads to DEST under their scan_as paths
```

`tools/build_sample_catalog.py` reads this catalogue (plus runtime-generated synthetic credential
shapes) to produce `web/samples.json`, which powers the **Sample library** on the web portal. A test
(`tests/test_web.py`) fails if the catalogue, the generated docs or `web/samples.json` are out of
date, or if any detector lacks a sample.

## Adding a use case

1. Copy `_template/use-case.json` into `use-cases/<category-slug>/<ID>/` and add
   `payload/<ID>.inert` (and optionally `benign/<ID>.inert`).
2. Fill in the metadata. Leave `expected.rules`, `mitre_atlas` and `owasp_asi` consistent with what
   the scanner reports for your payload.
3. Run `python tools/use_cases.py validate && python tools/use_cases.py render`, then
   `python tools/build_sample_catalog.py`, and finally the test suite.
