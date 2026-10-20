FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        build-essential \
        ca-certificates \
        clang \
        curl \
        git \
        gh \
        jq \
        libcrypt-dev \
        libpcre2-dev \
        libseccomp-dev \
        libssl-dev \
        lldb \
        openssl \
        perl \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        redis-server \
        redis-tools \
        ripgrep \
        shellcheck \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install 1.88.0 --profile minimal --component clippy --component llvm-tools-preview \
    && rustup toolchain install 1.91.0 --profile minimal --component clippy \
    && rustup toolchain install nightly-2025-11-23 --profile minimal \
    && rustup toolchain install nightly --profile minimal --component rustfmt --component clippy --component miri --component rust-src \
    && rustup toolchain install stable --profile minimal \
    && rustup default 1.88.0

RUN python3 -m venv /opt/tacacs-python \
    && /opt/tacacs-python/bin/python -m pip install --no-cache-dir \
        pyang==2.7.1 pytest==8.4.2 PyYAML==6.0.3 tomlkit==0.15.2

RUN cargo +stable install --locked --root /opt/tacacs-tools \
        cargo-audit cargo-fuzz cargo-llvm-cov cargo-outdated cargo-udeps mdbook

RUN cargo +stable install cargo-cyclonedx --version 0.5.9 --locked --root /opt/tacacs-tools

COPY --from=bufbuild/buf:1.47.2 /usr/local/bin/buf /usr/local/bin/buf

ENV PATH="/home/vscode/.local/bin:/opt/tacacs-python/bin:/opt/tacacs-tools/bin:/opt/tacacs-test-server/sbin:${PATH}"
ENV TACPLUS_SERVER_BINARY=/opt/tacacs-test-server/sbin/tac_plus-ng \
    TACPLUS_LIBRARY_DIR=/opt/tacacs-test-server/lib

COPY bootstrap-source.sh initialize-workspace.sh post-create.sh install-tacplus.sh /usr/local/share/tacacs-rs/
RUN chmod 755 /usr/local/share/tacacs-rs/*.sh \
    && mkdir -p /workspaces/tacacs-rs /home/vscode/.vscode-server \
    && chown vscode:vscode /workspaces/tacacs-rs /home/vscode/.vscode-server

RUN bash /usr/local/share/tacacs-rs/install-tacplus.sh
