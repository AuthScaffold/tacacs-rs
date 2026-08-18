# Container build for the central TACACS+ client agent (`tacacsrs-agentd`).
#
# Targets:
#   build   Build the image with `docker buildx` and load it into local Docker
#   push    Push the built image to $(REGISTRY)
#   test    Run the agent daemon test suite inside the build container
#   clean   Remove local Cargo build artifacts
#
# Override the image name and version as follows:
#   make build REGISTRY=ghcr.io/authscaffold BUILD_VERSION=2026.0706.1

IMAGE_NAME := tacacsrs-agentd
DOCKERFILE := Dockerfile

# The build context is the workspace root. The Dockerfile requires all manifests
# and crates under `libraries/` and `executables/`.
CONTEXT := ../..

# This list contains the target platforms. A non-amd64 tag has an architecture
# suffix. The support matrix does not include arm64.
PLATFORMS := linux/amd64 # linux/arm64

# The package version is embedded in the image metadata and binary.
BUILD_VERSION ?= dev
# The registry tag can identify an immutable staging image before promotion.
IMAGE_TAG ?= $(BUILD_VERSION)
SOURCE_URL ?= https://github.com/AuthScaffold/tacacs-rs
REVISION ?= unknown

# The container registry namespace. The default local namespace does not refer
# to a private registry. For example, set `REGISTRY=ghcr.io/authscaffold`.
REGISTRY ?= tacacsrs

.PHONY: all build push test clean

all: build

build:
	@echo "==> Build $(IMAGE_NAME)"
	@for p in $(PLATFORMS); do \
		arch=$$(echo $$p | cut -d/ -f2-); \
		tag=$(IMAGE_TAG); \
		if [ "$$arch" != "amd64" ]; then tag="$$tag-$$arch"; fi; \
		full_tag=$(REGISTRY)/$(IMAGE_NAME):$$tag; \
		echo "Build for $$p with tag $$full_tag"; \
		docker buildx build \
			--platform $$p \
			--file $(DOCKERFILE) \
			--tag $$full_tag \
			--build-arg BUILD_VERSION="$(BUILD_VERSION)" \
			--build-arg SOURCE_URL="$(SOURCE_URL)" \
			--build-arg REVISION="$(REVISION)" \
			--load \
			$(CONTEXT); \
	done

push:
	@echo "==> Push $(IMAGE_NAME)"
	@for p in $(PLATFORMS); do \
		arch=$$(echo $$p | cut -d/ -f2-); \
		tag=$(IMAGE_TAG); \
		if [ "$$arch" != "amd64" ]; then tag="$$tag-$$arch"; fi; \
		full_tag=$(REGISTRY)/$(IMAGE_NAME):$$tag; \
		echo "Push $$full_tag"; \
		docker push $$full_tag; \
	done

test:
	@echo "==> Run tests for $(IMAGE_NAME)"
	@for p in $(PLATFORMS); do \
		docker buildx build \
			--platform $$p \
			--file $(DOCKERFILE) \
			--target test \
			--build-arg CACHEBUST=$$(date +%s) \
			$(CONTEXT); \
	done

clean:
	@cargo clean
