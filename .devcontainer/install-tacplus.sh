#!/usr/bin/env bash
set -euo pipefail

revision=70bf938b542d63bca00d50be0874a38a290319e0
prefix=$(realpath -m "${1:-/opt/tacacs-test-server}")
if [[ -e "$prefix" ]] && { [[ ! -d "$prefix" ]] || [[ -n "$(find "$prefix" -mindepth 1 -maxdepth 1 -print -quit)" ]]; }; then
    printf 'Installation directory must be new or empty: %s\n' "$prefix" >&2
    exit 1
fi

build_root=$(mktemp -d /tmp/tacacs-server-build.XXXXXX)
trap 'rm -rf -- "$build_root"' EXIT
git init --quiet "$build_root"
git -C "$build_root" remote add origin https://github.com/MarcJHuber/event-driven-servers.git
git -C "$build_root" fetch --depth 1 origin "$revision"
git -C "$build_root" checkout --quiet --detach FETCH_HEAD
[[ "$(git -C "$build_root" rev-parse HEAD)" == "$revision" ]]

cd "$build_root"
./configure --prefix="$prefix" --libdir="$prefix/lib" --libarchdir="$prefix/lib" \
    --with-cc=cc --with-ssl --with-pcre2 \
    --without-curl --without-ares --without-pam --without-ldap \
    --without-freeradius --without-radcli --without-doc tac_plus-ng
make -j2
make install
printf '%s\n' "$revision" > "$prefix/source-revision"
LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$prefix/sbin/tac_plus-ng" -v