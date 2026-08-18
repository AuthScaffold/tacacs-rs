FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        git \
        libseccomp-dev \
        libssl-dev \
        lldb \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install 1.88.0 --profile minimal --component clippy \
    && rustup toolchain install nightly --profile minimal --component rustfmt \
    && rustup default 1.88.0
