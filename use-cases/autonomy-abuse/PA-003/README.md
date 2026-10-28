# PA-003: VS Code auto-approves all chat tools

> VS Code auto-approves all chat tools

- **Category:** PA · Autonomy & Platform-Config Abuse
- **Platforms:** vscode
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `MCP-CONFIG`, `VSCODE-AUTOAPPROVE`
- **MITRE ATLAS:** AML.T0010.005, AML.T0053, AML.T0081
- **OWASP ASI:** ASI03, ASI04, ASI05

## Why it works

Auto-approving every tool call lets the agent run commands with no confirmation.

## Mitigations

- Keep chat.tools.autoApprove off.
- Review .vscode/settings.json changes.

## Artifacts

- `payload/.vscode/settings.json` → scanned as `.vscode/settings.json`

## Benign look-alike

- `benign/.vscode/settings.json` → scanned as `.vscode/settings.json`

> Payloads are **defanged** and for defensive testing only. Do not run them.
