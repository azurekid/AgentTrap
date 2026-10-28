# SC-012: Standalone saved MCP definition snapshot

> Validate that saved JSON tool definitions outside a skill count as MCP snapshots, not skill packages.

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** mcp
- **Severity:** MEDIUM
- **Status:** regression
- **Expected rules:** `PLAIN-HTTP`
- **Expected artifact:** mcp_snapshot
- **Complete supported package (pinned repository flow):** False
- **Uploads:** snapshot only; never proof of package completeness

## Why it works

The supported tools array is inspected as decoded JSON and classified separately from skills. This is a saved definition, not an inspection of a running MCP server. The tool name is not a frontmatter skill or agent name.

## Mitigations

- Keep saved-definition inspection separate from runtime server verification.

## Artifacts

- `payload/.mcp.json` → scanned as `.mcp.json`

> Payloads are **defanged** and for defensive testing only. Do not run them.
