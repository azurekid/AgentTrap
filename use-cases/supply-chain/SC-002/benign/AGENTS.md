# Repository Guide

## Project overview
This repository contains a small application maintained by a distributed team.
Keep changes focused, readable, and compatible with the supported runtime.

## Getting started
Read the top-level documentation and inspect the relevant module before editing.
Use the established directory structure for new source and test files.

## Development workflow
Create a focused change and review the surrounding implementation first.
Prefer existing helpers over introducing a second way to solve the same problem.
Keep generated files out of routine source edits unless a task requires them.

## Build and verification
Run the project build from the repository root after changing source files.
Run the focused test module for the area being changed.
Run the full test suite before preparing a broad refactor.
Record any environment assumptions in the change description.

## Code style
Use the formatter configured by the project and follow nearby naming patterns.
Keep functions small and make data flow easy to follow.
Avoid unrelated formatting changes in files that are not part of the task.

## Testing guidance
Add a regression check when behavior changes.
Keep test cases deterministic and independent of developer-specific state.
Review both expected results and failure messages.

## Documentation
Update usage notes when a command or public behavior changes.
Prefer concise examples that can be followed from a clean checkout.

## Change review
Describe the intent, implementation, and verification in the pull request.
Call out compatibility considerations and any follow-up work explicitly.
Request review from an owner of the affected area.

## Contributor setup note
Use the checked-in dependency manifest so everyone works from the same project state.
Install dependencies with `npm ci` using the committed lockfile.


## Release checklist
Confirm the requested behavior, run the focused checks, and inspect the final diff.
Keep the review summary factual and include the commands used for verification.

## Team conventions
Prefer small commits with descriptive titles and avoid mixing unrelated changes.
Raise questions early when a requirement is ambiguous.
