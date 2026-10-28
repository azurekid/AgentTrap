# SC-003: MCP server launched via npx -y from a registry

> MCP server launched via npx -y from a registry

- **Category:** SC · Supply Chain & Dependency Trust
- **Platforms:** cursor, mcp
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `MCP-CONFIG`, `NPX-YES`
- **MITRE ATLAS:** AML.T0010.005, AML.T0011.001, AML.T0053, AML.T0081
- **OWASP ASI:** ASI04

## Why it works

npx -y installs and runs an MCP server with no review or version pin, matching a real malicious-MCP incident.

## Mitigations

- Pin MCP server versions and digests.
- Review new MCP servers before enabling.

## Artifacts

- `payload/.cursor/mcp.json` → scanned as `.cursor/mcp.json`

## References

- https://atlas.mitre.org/studies/AML.CS0053

> Payloads are **defanged** and for defensive testing only. Do not run them.
