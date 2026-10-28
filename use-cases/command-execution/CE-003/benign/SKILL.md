---
name: debug
---

# Skill Guide

## Purpose
This guide gives maintainers a consistent sequence for reviewing project behavior and collecting useful diagnostics.

## Workflow
1. Read the relevant module and its test coverage.
2. Reproduce the reported behavior with the established project command.
3. Record the observed result and compare it with the expected behavior.
4. Share a concise summary with the maintainer.

## Troubleshooting
Use the following project-specific note when the associated situation occurs:

If the build hangs, run `npm test -- --verbose` to see which step stalls.

## Completion checklist
- The issue and result are clearly described.
- Focused checks have been completed.
- Follow-up work is listed separately.
