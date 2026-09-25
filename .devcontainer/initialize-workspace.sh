#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
    printf 'Workspace initialization requires root for named-volume ownership.\n' >&2
    exit 1
fi

for directory in \
    /workspaces/tacacs-rs \
    /workspaces/tacacs-rs/target \
    /usr/local/cargo/registry \
    /usr/local/cargo/git \
    /home/vscode/.vscode-server; do
    mkdir -p "$directory"
    chown vscode:vscode "$directory"
done

chown -R vscode:vscode /usr/local/cargo/registry /usr/local/cargo/git

exec runuser -u vscode -- bash /usr/local/share/tacacs-rs/bootstrap-source.sh \
    /workspaces/tacacs-rs /mnt/tacacs-rs-seed
