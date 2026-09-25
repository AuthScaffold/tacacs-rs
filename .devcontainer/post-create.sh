#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/tacacs-rs

case "$(findmnt -n -o FSTYPE -T "$PWD")" in
    9p|drvfs|fuse.*)
        printf 'Source is not on a native Linux filesystem. Check workspaceMount before editing.\n' >&2
        exit 1
        ;;
esac

cargo fetch --locked
python3 -m unittest discover -s .devcontainer -p 'test_*.py' -v

printf '\nWorkspace ready: %s\n' "$PWD"
git log -1 --format='%h %s'
printf 'Refactor plan: docs/architecture/migration-and-decisions.md\n'