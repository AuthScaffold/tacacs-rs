# syntax=docker/dockerfile:1.7
#
# Container image for the central TACACS+ client agent (`tacacsrs-agentd`).
#
# This build has these stages:
#   base    -> Rust toolchain plus the build dependencies for the `psk` feature
#   test    -> agent daemon test suite (used by `make test`)
#   build   -> `tacacsrs-agentd` binary compiled with BuildKit caches
#   runtime -> image with only the binary and its runtime dependencies
#
# The build context must be the workspace root. Cargo requires all manifests and
# crates under `libraries/` and `executables/`. The local Makefile sets this context.
#
# You can override the base images with build arguments. Thus, you can use a
# different toolchain or a hardened runtime image without a file change:
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

# `tacacsrs-networking` links to the system OpenSSL for TLS and PSK support.
# Thus, the build requires `pkg-config` and `libssl-dev`.
# The vendored `protoc-bin-vendored` crate supplies `protoc`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the Cargo workspace. Cargo requires all workspace members to resolve the
# virtual workspace, including builds of one package.
COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY libraries ./libraries
COPY executables ./executables

# The sample certificate files for the networking crate are worktree symlinks.
# Copy the target files into the image. This copy supports Windows checkouts
# that do not preserve symlinks.
RUN rm -f libraries/tacacsrs_networking/examples/samples/client.*
COPY lde/containers/config/certificates/client.* ./libraries/tacacsrs_networking/examples/samples/

# -----------------------------------------------------------------------------
# test: run the agent daemon test suite
# -----------------------------------------------------------------------------
FROM base AS test
ARG FEATURES=
# Set `CACHEBUST` to force `make test` to run again with cached source layers.
# For example, pass `--build-arg CACHEBUST=$(date +%s)`.
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
# The cache mount decreases rebuild time but is not part of the image layer.
# Copy the new binary from the cached target directory in the same `RUN`.
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
# runtime: image with only the binary and its runtime dependencies
# -----------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

# `libssl3` supplies the OpenSSL runtime dependency for TLS and PSK support.
# `ca-certificates` supplies the trust store for certificate-based TLS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/tacacs

COPY --from=build /build/tacacsrs-agentd /usr/sbin/tacacsrs-agentd

# The agent runs as a foreground process. The default `CMD` matches the SONiC
# systemd unit. Override it for other environments.
# If the agent does not read the SONiC ConfigDB, remove `--sonic`.
ENTRYPOINT ["/usr/sbin/tacacsrs-agentd"]
CMD ["--sonic", "--listen-endpoint", "/run/tacacs/tacacs.sock", "--socket-mode", "666", "-vv"]
