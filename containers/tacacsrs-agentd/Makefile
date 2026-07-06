# Container build for the central TACACS+ client agent (`tacacsrs-agentd`).
#
# Targets:
#   build   Build the image with `docker buildx` (loads it into the local docker)
#   push    Push the built image to $(REGISTRY)
#   test    Run the agent daemon test suite inside the build container
#   clean   Remove local Cargo build artifacts
#
# The image name and version are overridable, for example:
#   make build REGISTRY=ghcr.io/authscaffold BUILD_VERSION=2026.0706.1

IMAGE_NAME := tacacsrs-agentd
DOCKERFILE := Dockerfile

# The build context is the workspace root so the Dockerfile can see the whole
# Cargo workspace (manifests plus every crate under libraries/ and executables/).
CONTEXT := ../..

# Space-separated list of target platforms. Non-amd64 tags are suffixed with the
# architecture. arm64 is left commented until it is part of the support matrix.
PLATFORMS := linux/amd64 # linux/arm64

# Image tag version. Override in CI with the computed release version.
BUILD_VERSION ?= dev

# Container registry / namespace. Defaults to a bare local namespace so the
# open-source build never references a private registry. Override for your own
# registry, e.g. REGISTRY=ghcr.io/authscaffold.
REGISTRY ?= tacacsrs

.PHONY: all build push test clean

all: build

build:
	@echo "==> Building $(IMAGE_NAME)..."
	@for p in $(PLATFORMS); do \
		arch=$$(echo $$p | cut -d/ -f2-); \
		tag=$(BUILD_VERSION); \
		if [ "$$arch" != "amd64" ]; then tag="$$tag-$$arch"; fi; \
		full_tag=$(REGISTRY)/$(IMAGE_NAME):$$tag; \
		echo "Building for $$p with tag $$full_tag..."; \
		docker buildx build \
			--platform $$p \
			--file $(DOCKERFILE) \
			--tag $$full_tag \
			--load \
			$(CONTEXT); \
	done

push:
	@echo "==> Pushing $(IMAGE_NAME)..."
	@for p in $(PLATFORMS); do \
		arch=$$(echo $$p | cut -d/ -f2-); \
		tag=$(BUILD_VERSION); \
		if [ "$$arch" != "amd64" ]; then tag="$$tag-$$arch"; fi; \
		full_tag=$(REGISTRY)/$(IMAGE_NAME):$$tag; \
		echo "Pushing $$full_tag..."; \
		docker push $$full_tag; \
	done

test:
	@echo "==> Testing $(IMAGE_NAME)..."
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
