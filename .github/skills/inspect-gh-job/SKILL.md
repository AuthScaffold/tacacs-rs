---
name: inspect-gh-job
description: 'Inspect GitHub Actions job logs using gh CLI. Use when: debugging CI failures, checking job output, diagnosing workflow errors, viewing action logs, investigating flaky tests, understanding why a job failed or is stuck.'
argument-hint: 'Paste the GitHub Actions job URL'
---

# Inspect GitHub Actions Job Logs

Retrieve and analyze GitHub Actions job logs using the `gh` CLI, handling both in-progress and completed runs.

## When to Use

- A CI job failed and you need to see why
- A job is still running but you want to check progress
- You need to diagnose flaky tests, token errors, or infrastructure issues

## Input

The user provides a GitHub Actions URL in one of these forms:

- Job URL: `https://github.com/{owner}/{repo}/actions/runs/{run_id}/job/{job_id}`
- Run URL: `https://github.com/{owner}/{repo}/actions/runs/{run_id}`

Extract `owner`, `repo`, `run_id`, and `job_id` from the URL.

## Procedure

### 1. Check Run Status

```bash
gh api repos/{owner}/{repo}/actions/runs/{run_id} --jq '{status: .status, conclusion: .conclusion, name: .name}'
```

- If `status` is `completed`, you can use `gh run view --log` directly.
- If `status` is `in_progress` or `queued`, `gh run view --log` will fail — use the API instead.

### 2a. Completed Run — Fetch Logs Directly

```bash
gh run view {run_id} --repo {owner}/{repo} --job {job_id} --log
```

If the output is large, pipe through `Select-Object -Last 150` (PowerShell) or `tail -150` (bash).

### 2b. In-Progress or Queued Run — Use API

First check the specific job's status:

```bash
gh api repos/{owner}/{repo}/actions/jobs/{job_id} --jq '{name: .name, status: .status, conclusion: .conclusion, started_at: .started_at, steps: [.steps[] | {name: .name, status: .status, conclusion: .conclusion}]}'
```

If the job itself is completed (even while the overall run is still going), fetch its logs:

```bash
gh api repos/{owner}/{repo}/actions/jobs/{job_id}/logs
```

### 3. Analyze Output

Look for:
- **Error lines**: `error`, `Error:`, `##[error]`, `failed`, exit codes
- **Token/auth issues**: "token required", "unauthorized", "forbidden"
- **Test failures**: `FAILED`, `test result: FAILED`, assertion messages
- **Timeout/hang**: job started long ago with no recent output
- **Deprecation warnings**: Node.js version warnings, action deprecations

### 4. Report Findings

Summarize:
1. **Root cause** — what specifically failed
2. **Impact** — does this block the pipeline or is it non-fatal?
3. **Fix** — concrete steps to resolve

## Notes

- `gh` must be authenticated (`gh auth status` to verify)
- For private repos, ensure the token has `actions:read` scope
- Job logs via API return raw text (timestamps + log lines)
- If no `job_id` is provided, list jobs first: `gh api repos/{owner}/{repo}/actions/runs/{run_id}/jobs --jq '.jobs[] | {id: .id, name: .name, conclusion: .conclusion}'`
