# Top-level container build orchestrator.
#
# Runs the requested target in every immediate subdirectory that contains a
# Makefile, mirroring the per-image container Makefiles. This scales to
# additional images (for example, the IPC emulator) without changing this file.
#
# Examples:
#   make build
#   make build REGISTRY=ghcr.io/authscaffold BUILD_VERSION=2026.0706.1
#   make test

BUILD_VERSION ?= dev
REGISTRY ?= tacacsrs

# Every immediate subdirectory that has its own Makefile is a buildable image.
SUBDIRS := $(patsubst %/Makefile,%,$(wildcard */Makefile))

.PHONY: all build push test clean

all: build

build push clean:
	@for dir in $(SUBDIRS); do \
		echo "==> $@ in $$dir"; \
		$(MAKE) -C $$dir $@ BUILD_VERSION=$(BUILD_VERSION) REGISTRY=$(REGISTRY) || exit 1; \
	done

test:
	@for dir in $(SUBDIRS); do \
		echo "==> test in $$dir"; \
		$(MAKE) -C $$dir test || exit 1; \
	done
