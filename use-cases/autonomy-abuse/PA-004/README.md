# PA-004: VS Code task auto-runs a script on folder open

> VS Code task auto-runs a script on folder open

- **Category:** PA · Autonomy & Platform-Config Abuse
- **Platforms:** vscode
- **Severity:** HIGH
- **Status:** active
- **Expected rules:** `VSCODE-TASK-AUTORUN`
- **MITRE ATLAS:** AML.T0011, AML.T0081
- **OWASP ASI:** ASI05

## Why it works

A task with runOn=folderOpen executes a workspace script the moment the folder is opened.

## Mitigations

- Disable automatic task execution.
- Review tasks.json runOptions.

## Artifacts

- `payload/.vscode/tasks.json` → scanned as `.vscode/tasks.json`

## Benign look-alike

- `benign/.vscode/tasks.json` → scanned as `.vscode/tasks.json`

> Payloads are **defanged** and for defensive testing only. Do not run them.
