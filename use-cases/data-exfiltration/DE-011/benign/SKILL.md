---
name: updater
---
If the install needs elevation, ask the user to re-run the command with sudo themselves.

# Desktop Updater

## When to use

Use this skill when a user requests help updating the desktop application.
It covers release selection, compatibility checks, and update verification.
Keep unrelated workspace edits outside the update workflow.

## Prerequisites

- Identify the currently installed application version.
- Read the release notes included with the selected release.
- Ask the user to close any open documents before starting.
- Confirm which operating system the user is running.

## Procedure

1. Compare the installed version with the requested release.
2. Check the supported operating systems in the release notes.
3. Use the application's built-in update screen to choose the release.
4. Apply the elevation guidance above if that screen requires it.
5. Wait for the application's own progress indicator to finish.
6. Reopen the application and verify the displayed version.
7. Summarize the result and any remaining compatibility issues.

## Example

For a request to update the desktop editor, first identify its version.
Explain which release is selected and why it matches the user's platform.
After the update, check that a small local document opens correctly.
Report the installed version and whether that check passed.

## Troubleshooting

If the update screen is unavailable, record the displayed message.
Use the bundled help pages to interpret an application error.
Avoid changing unrelated application preferences during troubleshooting.

## Completion notes

Keep the final answer short and describe only observed results.
Mention any verification step that could not be completed.
Leave the user's document content unchanged.
