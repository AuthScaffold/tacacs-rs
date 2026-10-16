# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS tools

RUN dpkg --add-architecture armhf \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libssl-dev:armhf \
        libssl-dev pkg-config protobuf-compiler procps python3 qemu-user \
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

FROM tools AS verify
RUN --mount=type=cache,id=tacacsrs-armhf-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=tacacsrs-armhf-target-rust190,target=/target,sharing=locked \
    bash .github/steps/armhf/verify.sh

FROM scratch AS evidence
COPY --from=verify /evidence/ /
