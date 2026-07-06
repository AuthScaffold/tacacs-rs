# syntax=docker/dockerfile:1.7
#
# Container image for the central TACACS+ client agent (`tacacsrs-agentd`).
#
# This is a multi-stage build:
#   base    -> Rust toolchain plus the build dependencies for the `psk` feature
#   test    -> runs the agent daemon's test suite (used by `make test`)
#   build   -> compiles the `tacacsrs-agentd` binary with BuildKit caches
#   runtime -> minimal image that ships only the binary and its runtime deps
#
# The build context MUST be the workspace root so the whole Cargo workspace
# (manifests plus every crate under `libraries/` and `executables/`) is visible.
# The container Makefile in this directory sets the context accordingly.
#
# The base images are overridable build arguments so downstream builders can
# swap in their own toolchain or hardened runtime base without editing this
# file, for example:
#
#   docker buildx build \
#       --build-arg BUILDER_IMAGE=<registry>/rust:1.90 \
#       --build-arg RUNTIME_IMAGE=<registry>/debian:bookworm-slim \
#       --file Dockerfile ../..

ARG BUILDER_IMAGE=docker.io/library/rust:1.90-bookworm
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim

# -----------------------------------------------------------------------------
# base: toolchain and build dependencies
# -----------------------------------------------------------------------------
FROM ${BUILDER_IMAGE} AS base

# `pkg-config` and `libssl-dev` are required because `tacacsrs-networking`
# links against the system OpenSSL for TLS and PSK support. `protoc` is
# provided by the vendored `protoc-bin-vendored` crate, so it does not need
# to be installed here.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the Cargo workspace. All workspace members must be present for cargo to
# resolve the virtual workspace, even when building a single package.
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY libraries ./libraries
COPY executables ./executables

# The networking crate sample certificate files are symlinks in the worktree.
# Materialize the files in the Linux build image so tests can follow the paths
# reliably even when the host checkout was created on Windows.
RUN rm -f libraries/tacacsrs_networking/examples/samples/client.*
COPY lde/containers/config/certificates/client.* ./libraries/tacacsrs_networking/examples/samples/

# -----------------------------------------------------------------------------
# test: run the agent daemon test suite
# -----------------------------------------------------------------------------
FROM base AS test
ARG FEATURES=
# CACHEBUST lets `make test` force a fresh test run even when the source layers
# are cached (pass --build-arg CACHEBUST=$(date +%s)).
ARG CACHEBUST=0
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo test --locked -p tacacsrs-agentd --features "${FEATURES}"

# -----------------------------------------------------------------------------
# build: compile the release binary
# -----------------------------------------------------------------------------
FROM base AS build
ARG PROFILE=release
ARG FEATURES=
# The cache mount speeds up rebuilds but is not part of the image layer, so the
# freshly built binary is copied out of the cached target dir within the same
# RUN before the mount is unmounted.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    if [ "${PROFILE}" = "debug" ]; then \
        cargo build --locked -p tacacsrs-agentd --features "${FEATURES}"; \
    else \
        cargo build --locked --profile "${PROFILE}" -p tacacsrs-agentd --features "${FEATURES}"; \
    fi \
    && cp "target/${PROFILE}/tacacsrs-agentd" /build/tacacsrs-agentd

# -----------------------------------------------------------------------------
# runtime: minimal image with just the binary and its runtime dependencies
# -----------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

# `libssl3` satisfies the OpenSSL runtime dependency for TLS and PSK support,
# and `ca-certificates` provides the trust store for certificate-based TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/tacacs

COPY --from=build /build/tacacsrs-agentd /usr/sbin/tacacsrs-agentd

# The agent runs as a foreground process. The default CMD mirrors the SONiC
# systemd unit and can be overridden at `docker run` time for other environments
# (for example, dropping `--sonic` when not reading SONiC ConfigDB).
ENTRYPOINT ["/usr/sbin/tacacsrs-agentd"]
CMD ["--sonic", "--listen-endpoint", "/run/tacacs/tacacs.sock", "--socket-mode", "666", "-vv"]
