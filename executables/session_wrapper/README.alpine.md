# Alpine Linux technical note

This note applies to the `session-wrapper` crate when it is built natively on Alpine Linux. The rest of the workspace does not install seccomp user-notification filters and is not affected by this `libseccomp` linking edge case.

## Summary

Alpine's Rust toolchain uses the `x86_64-unknown-linux-musl` target, and that target defaults to the static musl C runtime (`crt-static`). `session-wrapper` also links to `libseccomp`. Combining the static musl runtime with a dynamically linked `libseccomp.so` can produce a binary that builds but crashes. The crash happens before the child can send its seccomp notification fd to the parent.

The crate build script rejects that unsafe combination when it can detect it. Use one of the supported build modes below instead.

## Symptoms

The most common runtime symptom is an early child setup failure:

```text
Error: failed to spawn session process

Caused by:
    0: failed to receive seccomp notification fd from child
    1: control socket closed before fd was received
```

With the newer parent-side diagnostics, the final cause can include a signal such as:

```text
control socket closed before fd was received; child 1234 terminated by signal 11 (SIGSEGV)
```

If traced with `gdb` or `strace`, the child can fault before the wrapper reports a Rust error, often around `libseccomp::api::get_api`, `seccomp_api_get`, or `ScmpFilterContext::new`.

## Preferred: static `libseccomp`

Use Alpine's static `libseccomp` package and tell Cargo to link it statically:

```bash
sudo apk add libseccomp-static

LIBSECCOMP_LINK_TYPE=static \
LIBSECCOMP_LIB_PATH=/usr/lib \
cargo build -p session-wrapper
```

When switching link modes, clean the crate first to avoid reusing old build artifacts:

```bash
cargo clean -p session-wrapper
```

The resulting binary must not depend on `libseccomp.so` at runtime:

```bash
file target/debug/session-wrapper
ldd target/debug/session-wrapper
```

On Alpine, musl's loader can still show a static PIE through `ldd`. Make sure that `libseccomp.so` does not appear in the list.

## Development-only: dynamic musl binary

For a local development build that intentionally depends on Alpine's shared libraries, disable musl CRT static linking:

```bash
RUSTFLAGS="-C target-feature=-crt-static" \
cargo build -p session-wrapper
```

This produces a normal dynamically linked Alpine binary. It is useful for quick VM debugging, but it is not the recommended packaging mode because the target machine must provide compatible shared libraries.

## Cross musl builds

When building `session-wrapper` for `x86_64-unknown-linux-musl` from a non-Alpine host, provide a musl-targeted static `libseccomp`:

```bash
export LIBSECCOMP_LIB_PATH=/path/to/libseccomp-musl/lib
export LIBSECCOMP_LINK_TYPE=static
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH=/path/to/libseccomp-musl/lib/pkgconfig

cargo build -p session-wrapper --target x86_64-unknown-linux-musl
```

CI follows this model by building and caching a static musl `libseccomp`.

## Quick validation

Run these commands to make sure that you know the active build mode:

```bash
rustc -vV
rustc --print cfg | grep 'target_feature="crt-static"'
readelf -l target/debug/session-wrapper | grep -A1 INTERP || true
ldd target/debug/session-wrapper
```

If `crt-static` is enabled and `libseccomp.so` appears in the dependency list, rebuild using the static `libseccomp` mode above.

## Do not bypass the build guard

The guard is there because the failure happens in the forked child before normal Rust error reporting can run. Bypassing it can recreate the original failure. The parent waits for the seccomp notification fd while the child segfaults first. The wrapper then reports only that the control socket closed before fd handoff.
