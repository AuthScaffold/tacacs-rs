# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM rust:1.91-bookworm@sha256:c1e5f19e773b7878c3f7a805dd00a495e747acbdc76fb2337a4ebf0418896b33 AS tools

RUN dpkg --add-architecture armhf \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libssl-dev:armhf \
        libssl-dev pkg-config protobuf-compiler procps python3 python3-pytest qemu-user redis-server openssl \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add armv7-unknown-linux-gnueabihf

ENV PROTOC=/usr/bin/protoc \
    CARGO_BUILD_TARGET=armv7-unknown-linux-gnueabihf \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUNNER="qemu-arm -L /" \
    CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc \
    AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-ar \
    PKG_CONFIG_LIBDIR_armv7_unknown_linux_gnueabihf=/usr/lib/arm-linux-gnueabihf/pkgconfig:/usr/share/pkgconfig \
    PKG_CONFIG_ALLOW_CROSS_armv7_unknown_linux_gnueabihf=1 \
    CARGO_TARGET_DIR=/target \
    CARGO_PROFILE_RELEASE_DEBUG=0

WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY libraries libraries
COPY executables executables
COPY lde/containers/config/certificates lde/containers/config/certificates
RUN rm -f libraries/tacacsrs_networking/examples/samples/client.*
COPY lde/containers/config/certificates/client.* libraries/tacacsrs_networking/examples/samples/
COPY .github/steps/armhf .github/steps/armhf
COPY tests/e2e tests/e2e

FROM tools AS verify
RUN --mount=type=cache,id=tacacsrs-armhf-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=tacacsrs-armhf-target-rust190,target=/target,sharing=locked \
    bash .github/steps/armhf/verify.sh

FROM scratch AS evidence
COPY --from=verify /evidence/ /
