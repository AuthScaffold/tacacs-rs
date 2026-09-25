FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        curl \
        git \
        gh \
        jq \
        libseccomp-dev \
        libssl-dev \
        lldb \
        pkg-config \
        python3 \
        python3-pip \
        python3-pytest \
        python3-venv \
        ripgrep \
        shellcheck \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install 1.88.0 --profile minimal --component clippy --component llvm-tools-preview \
    && rustup toolchain install nightly --profile minimal --component rustfmt --component clippy --component miri \
    && rustup toolchain install stable --profile minimal \
    && rustup default 1.88.0

RUN cargo +stable install --locked --root /opt/tacacs-tools \
        cargo-audit cargo-fuzz cargo-llvm-cov cargo-outdated cargo-udeps mdbook

COPY --from=bufbuild/buf:1.47.2 /usr/local/bin/buf /usr/local/bin/buf

ENV PATH="/opt/tacacs-tools/bin:${PATH}"

COPY bootstrap-source.sh initialize-workspace.sh post-create.sh /usr/local/share/tacacs-rs/
RUN chmod 755 /usr/local/share/tacacs-rs/*.sh \
    && mkdir -p /workspaces/tacacs-rs /home/vscode/.vscode-server \
    && chown vscode:vscode /workspaces/tacacs-rs /home/vscode/.vscode-server
