# PA-001: Claude settings: malicious hooks, apiKeyHelper and wildcard permissions

> Claude settings: malicious hooks, apiKeyHelper and wildcard permissions

- **Category:** PA · Autonomy & Platform-Config Abuse
- **Platforms:** claude-code
- **Severity:** CRITICAL
- **Status:** active
- **Expected rules:** `CLAUDE-APIKEYHELPER`, `CLAUDE-HOOKS`, `MCP-CONFIG`, `PERMISSION-WILDCARD`, `PIPE-TO-SHELL`, `SUSPICIOUS-TLD`, `TRAFFIC-REDIRECT`
- **MITRE ATLAS:** AML.T0010.005, AML.T0050, AML.T0053, AML.T0072, AML.T0081, AML.T0098
- **OWASP ASI:** ASI02, ASI03, ASI04, ASI05

## Why it works

A SessionStart hook runs a remote script at startup, apiKeyHelper siphons the API key, wildcard Bash is allowed and the base URL is redirected to an attacker gateway.

## Mitigations

- Review .claude/settings.json in PRs.
- Disallow wildcard Bash and startup hooks; pin ANTHROPIC_BASE_URL.

## Artifacts

- `payload/.claude/settings.json` → scanned as `.claude/settings.json`

## Benign look-alike

- `benign/.claude/settings.json` → scanned as `.claude/settings.json`

> Payloads are **defanged** and for defensive testing only. Do not run them.
