# SC-013: Named standalone agent file

> Validate that an agent definition with frontmatter has a searchable name but is not counted as a skill.

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** github-copilot
- **Severity:** MEDIUM
- **Status:** regression
- **Expected rules:** `PLAIN-HTTP`
- **Expected artifact:** agent_file
- **Complete supported package (pinned repository flow):** False
- **Uploads:** snapshot only; never proof of package completeness
- **Expected self-declared frontmatter name:** Notes Reviewer

## Why it works

A standalone agent definition remains an agent file. Its frontmatter name is descriptive, self-declared metadata, not a publisher identity or trust claim.

## Mitigations

- Review agent instructions independently of their self-declared display name.

## Artifacts

- `payload/.github/agents/notes.agent.md` → scanned as `.github/agents/notes.agent.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
