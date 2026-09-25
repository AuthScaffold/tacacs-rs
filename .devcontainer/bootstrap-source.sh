#!/usr/bin/env bash
set -euo pipefail

workspace=${1:-/workspaces/tacacs-rs}
seed=${2:-/mnt/tacacs-rs-seed}

fail() {
    printf 'Source bootstrap: %s\n' "$*" >&2
    exit 1
}

mkdir -p "$workspace"
workspace=$(realpath "$workspace")

if [[ -e "$workspace/.git" ]]; then
    [[ -d "$workspace/.git" && ! -L "$workspace/.git" ]] || fail 'The workspace must have its own .git directory, not a linked worktree.'
    git -C "$workspace" rev-parse --verify HEAD >/dev/null 2>&1 ||
        fail 'The source volume contains an incomplete repository. Inspect it before retrying.'
    printf 'Keeping the existing Linux checkout at %s. No fetch, reset, or checkout was performed.\n' "$workspace"
    exit 0
fi

while IFS= read -r -d '' entry; do
    [[ "$entry" == "$workspace/target" && -d "$entry" && ! -L "$entry" ]] ||
        fail 'The source volume is not empty. Inspect its contents before importing a repository.'
done < <(find "$workspace" -mindepth 1 -maxdepth 1 -print0)

[[ -d "$seed/.git" && ! -L "$seed/.git" ]] || fail 'The read-only seed must be a checkout with its own .git directory.'
seed=$(realpath "$seed")
[[ "$seed" != "$workspace" ]] || fail 'The seed and workspace must be different directories.'

seed_git() {
    git -c safe.directory="$seed" -c core.fsmonitor=false -C "$seed" "$@"
}

branch=$(seed_git symbolic-ref --quiet --short HEAD) ||
    fail 'The seed has a detached HEAD. Create or select a branch before rebuilding.'
revision=$(seed_git rev-parse --verify HEAD)
[[ -z "$(seed_git status --porcelain --untracked-files=no)" ]] ||
    fail 'The seed has tracked changes. Save editor buffers and commit those changes before rebuilding.'

origin=$(seed_git remote get-url origin 2>/dev/null || true)
git init --quiet "$workspace"
git -C "$workspace" config core.autocrlf false
git -C "$workspace" config core.fsmonitor false
git -c safe.directory="$seed" -c core.fsmonitor=false -C "$workspace" fetch --quiet --no-tags "$seed" "$revision"
git -C "$workspace" checkout --quiet -b "$branch" FETCH_HEAD
[[ "$(git -C "$workspace" rev-parse HEAD)" == "$revision" ]] || fail 'The imported revision does not match the seed.'

if [[ -n "$origin" ]]; then
    git -C "$workspace" remote add origin "$origin"
fi

printf 'Imported branch %s at %s into %s.\n' "$branch" "$revision" "$workspace"
printf 'The host checkout is now a read-only seed, not a synchronized working copy.\n'
untracked_count=$(seed_git ls-files --others --exclude-standard -z | tr -cd '\0' | wc -c)
if [[ "$untracked_count" -gt 0 ]]; then
    printf '%s untracked files remain in %s. Copy only the files you need after reviewing them.\n' "$untracked_count" "$seed"
fi
printf 'Refactor plan: docs/architecture/migration-and-decisions.md\n'