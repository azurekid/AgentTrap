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
    payload/<scan_as>     the complete, defanged attack file under its real name
                          (payload/AGENTS.md, payload/.claude/settings.json, ...)
    benign/<scan_as>      optional clean look-alike that must NOT trigger HIGH/CRITICAL
```

## Safety rules

- **Every payload is inert and defanged.** Hosts use `.example`/`.invalid` domains or documented
  canaries; credentials are synthetic shapes, never live values. Never run a payload.
- Payloads are complete, realistic files stored under their **real names**, so they can be
  inspected and uploaded as-is. The attack is buried in otherwise ordinary content, as it would
  be in the wild. `artifacts[].scan_as` records the path a scanner should treat the file as.
- ⚠️ Because the names are real, an agent whose working directory is inside a case folder (or
  that loads nested `AGENTS.md` files) may load a payload. Do not run coding agents from inside
  `use-cases/`, and do not copy a payload into a real project. [AGENTS.md](AGENTS.md) in this
  folder tells agents that load nested instructions to treat everything below as hostile data.
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
   `payload/<scan_as>` (and optionally `benign/<scan_as>`), for example `payload/AGENTS.md`.
2. Fill in the metadata. Leave `expected.rules`, `mitre_atlas` and `owasp_asi` consistent with what
   the scanner reports for your payload.
3. Run `python tools/use_cases.py validate && python tools/use_cases.py render`, then
   `python tools/build_sample_catalog.py`, and finally the test suite.
