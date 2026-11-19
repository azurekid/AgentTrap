# AgentLens production cutover

Status: Validated

## Target

Azure Hacking (MVP 2026), West Europe, new `rg-agentlens`. Reuse the repository's Azure CLI and Bicep deployment path. Keep the existing App Service, storage and workflow target unchanged until the replacement is verified.

## Sequence

1. Inventory the production app and private archive metadata without reading scan contents.
2. Verify local tests, compile the Bicep and run an incremental Azure what-if.
3. Provision the parallel stack and test code deployment.
4. Leave expiring investigation and feedback blobs in the original private container under the original lifecycle rules. Do not copy them into the new container because Azure resets the modification timestamp on copy. Copy only persistent statistics and fingerprints during a controlled write pause, using Entra authentication and checksum verification.
5. Switch GitHub OIDC deployment to the new app. Verify Latest News, RSS, newsletter archive, scanner, and retained state. Leave old resources available for rollback.

## Validation proof

2026-11-19: For `fcde1d3`, GitHub Actions passed the test job. The Bicep validation helper passed CLI, authentication, compilation, ARM validation and what-if for the existing West Europe `rg-agentlens`. The full ARM preview showed no resource deletions and new resources only for the private news container and app reader role. `az bicep lint` and `git diff --check` passed. The resource-group policy query returned no assignments; ARM accepted the template. The live plan is B1, matching the template parameters.

- [x] All validation checks pass
  - [x] Core validation: CLI, authentication, build, ARM validation and what-if
  - [x] Optional linting: Bicep compiler and shell/YAML checks
  - [x] Azure Policy validation

2026-11-19: 509 Python tests and 13 subtests passed. The AgentLens Bicep compiled, and workflow YAML and shell syntax checks passed. The Bicep `validate-deployment.sh` helper passed with the subscription explicitly selected: 13 creates, no modifications or deletions. The Azure Policy MCP query reviewed inherited MFA, diagnostics, networking and Defender policies. The Bicep role assignment gives the new app identity Blob Data Contributor at the archive-container scope only.
