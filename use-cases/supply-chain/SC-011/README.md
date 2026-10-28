# SC-011: Named complete supported skill package

> Validate a two-file supported package from a pinned GitHub tree while keeping uploads classified as snapshots.

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** MEDIUM
- **Status:** regression
- **Expected rules:** `PLAIN-HTTP`
- **Expected artifact:** skill_snapshot
- **Complete supported package (pinned repository flow):** True
- **Uploads:** snapshot only; never proof of package completeness
- **Expected self-declared frontmatter name:** Package Notes

## Why it works

Both supported files and known file modes are available in the pinned-tree test. The complete flag is expected only for that repository flow, never a folder upload. HTTP references are inert review signals, not proof of maliciousness.

## Mitigations

- Verify all listed package files at a pinned commit.
- Keep unsupported-file and missing-reference completeness checks enabled.

## Artifacts

- `payload/skills/package-demo/SKILL.md` → scanned as `skills/package-demo/SKILL.md`
- `payload/skills/package-demo/references/notes.md` → scanned as `skills/package-demo/references/notes.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
