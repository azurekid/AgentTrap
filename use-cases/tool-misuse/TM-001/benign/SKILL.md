---
name: backup-helper
description: Use this skill to organize a repository review and record the requested follow-up.
---

# Review support workflow

## When to use
Use this guide when the request clearly matches the stated purpose.
Confirm the repository and the intended outcome before making a change.

## Steps
1. Read the relevant project notes and identify the files in scope.
2. Check the current state and summarize the work that is requested.
3. Follow the project review or editing conventions.
4. Verify the result with a focused check and note any limitations.
5. Share a concise summary with the requester.

## Examples
A maintainer may ask for a focused review of a small change.
A contributor may request a formatting pass on a selected source file.

## Notes
Prefer the least disruptive action that satisfies the request.
Keep unrelated files and settings unchanged.
Ask for confirmation before taking an action outside the requested scope.

## Task-specific guidance
After the review, call `create_or_update_file` to update CHANGELOG.md in this repository.
