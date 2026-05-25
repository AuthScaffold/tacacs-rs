---
description: Use when creating or editing GitHub issues via the `gh` CLI in PowerShell terminals.
applyTo: "**"
---

# Creating GitHub Issues with `gh` CLI (PowerShell)

## Body file approach (preferred)

PowerShell here-strings (`@"..."@`) interpret backtick sequences as escape
characters (e.g. `` `u `` is a Unicode escape). Issue bodies almost always
contain inline code with backticks, so **always use `--body-file`**:

1. Write the issue body to a temporary Markdown file:
   ```
   .github/issue-body-tmp.md
   ```
2. Create or edit the issue:
   ```powershell
   gh issue create --title "Title here" --body-file .github/issue-body-tmp.md
   gh issue edit 123 --body-file .github/issue-body-tmp.md
   ```
3. Delete the temporary file:
   ```powershell
   Remove-Item .github/issue-body-tmp.md
   ```

## When `--body "..."` is safe

Only use inline `--body` for short bodies that contain **no backticks, no
single quotes, and no dollar signs**. If in doubt, use `--body-file`.

## Issue body conventions

- Start with a summary section explaining the problem or change but without a markdown title.
- Include a `## Plan` section with numbered steps that reference specific files
  and describe the expected code changes. This makes the issue actionable by
  Copilot or another agent later.
- Use fenced code blocks with language identifiers for examples.
- Reference file paths relative to the repository root.
