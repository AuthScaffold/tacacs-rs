# Copilot Instructions

- Before preparing a commit or considering Rust code changes complete, run the relevant local checks that mirror CI.
- Run rustfmt with the same nightly command CI expects: `cargo +nightly fmt --all -- --check`, and if it fails, run `cargo +nightly fmt --all` to apply fixes.
- Run clippy with the same scope and warning policy used by CI: `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Run docs with warnings denied: `cargo doc --workspace --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"`.
- Run tests for code changes that can affect behavior or public APIs: `cargo test --workspace --all-features`.
- Run a workspace build for code changes that can affect compilation: `cargo build --workspace`.
- Do not leave formatting changes, clippy warnings, rustdoc warnings, test failures, or build failures unresolved before commit.
- If a relevant check cannot be run in the current environment, say so explicitly and note that CI requires the corresponding job to pass cleanly.

## CI Alignment

- Pull request CI runs rustfmt as `cargo +nightly fmt --all -- --check`.
- Pull request CI runs clippy as `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Pull request CI runs docs as `cargo doc --workspace --no-deps --all-features` with `RUSTDOCFLAGS="-D warnings"`.
- Pull request CI runs tests as `cargo test --workspace --all-features`.
- Pull request CI runs workspace builds as `cargo build --workspace --release --target <target>` for Linux GNU, Linux MUSL, and Windows MSVC targets, depending on the job.
- Coverage CI runs `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info`.
- SBOM CI runs `cargo cyclonedx --format json --all --all-features` and `cargo cyclonedx --format xml --all --all-features`.
- Security audit CI generates a lockfile with `cargo generate-lockfile` and then runs `cargo audit` behavior through `rustsec/audit-check`; this is mainly relevant when dependencies change.
- Debian packaging CI builds `tacon`, generates the man page, and runs `cargo deb --package tacon --no-build --dbgsym`; this is relevant when CLI, packaging, or Debian assets change.