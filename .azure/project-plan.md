# SkillVenom web application: approved scope

The user approved implementation, deployment artifacts (Bicep, scripts, CI/CD), not resource provisioning.

## Architecture

- One Python/FastAPI application imports the existing scanner through a time-limited subprocess.
- Same-origin, dependency-free HTML/CSS/JavaScript dashboard; no frontend build is needed.
- File and folder uploads plus public GitHub repository URLs. Repository default branches are pinned to commit SHAs.
- Reuse existing agent Markdown/configuration discovery, including the test fixtures; workflows remain opt-in.
- Show per-file findings, line numbers, source references, severity filters, honest heuristic verdicts, and JSON exports.
- Extend Python and PowerShell with shared credential detection rules and redacted finding snippets.
- Do not execute uploaded instructions, repository scripts, hooks, MCP servers, or Markdown content.

## Public access and archiving decisions

- Public interface without login, with bounded uploads/downloads/expansion, concurrency limits, request rate limiting, same-origin browser requests, and isolated scanner timeouts.
- Archive original files with HIGH/CRITICAL findings when the pre-checked *Allow investigation retention* consent checkbox is left on; users may opt out. A pre-submission disclosure explains retention; anonymous statistics are always recorded.
- Default retention is 30 days; private local archive for development, private Azure Blob Storage for deployment.
- Archive access is operator-only through filesystem/Azure RBAC; there is no public archive API.
- Surface archive failures separately from scan results.
- Azure uses managed identity and a verified-by-operator 30-day lifecycle policy. Deployment documentation must explain WAF/edge controls and single-worker rate-limit boundaries.

## Delivery

Local application, regression/API/archive tests, browser validation, Bicep infrastructure (`infra/`), an az CLI deployment script, and a GitHub Actions OIDC deployment workflow. Approved choices: plain Bicep (no azd), App Service B1 Linux, westeurope, no Front Door. Running the deployment against a subscription requires separate approval.
