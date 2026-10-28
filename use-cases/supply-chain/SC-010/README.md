# SC-010: Named partial skill snapshot

> Validate named skill grouping without claiming completeness when a referenced file is missing.

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** any-agent
- **Severity:** MEDIUM
- **Status:** regression
- **Expected rules:** `PLAIN-HTTP`
- **Expected artifact:** skill_snapshot
- **Complete supported package (pinned repository flow):** False
- **Uploads:** snapshot only; never proof of package completeness
- **Expected self-declared frontmatter name:** Snapshot Notes

## Why it works

The missing local reference prevents a complete-package claim, even when the submitted skill file was fully inspected. The inert HTTP reference keeps the snapshot visible in findings-only report views.

## Mitigations

- Inspect missing references before making a completeness claim.
- Do not interpret a content fingerprint or self-declared name as approval.

## Artifacts

- `payload/skills/snapshot-demo/SKILL.md` → scanned as `skills/snapshot-demo/SKILL.md`

> Payloads are **defanged** and for defensive testing only. Do not run them.
