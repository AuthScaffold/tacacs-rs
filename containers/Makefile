# Top-level container build targets.
#
# This Makefile runs the requested target in each immediate subdirectory that
# contains a Makefile. Each image uses the targets in its local Makefile.
# A new image, such as the IPC emulator, does not require a change to this file.
#
# Examples:
#   make build
#   make build REGISTRY=ghcr.io/authscaffold BUILD_VERSION=2026.0706.1
#   make test

BUILD_VERSION ?= dev
REGISTRY ?= tacacsrs

# Each immediate subdirectory with a Makefile contains a buildable image.
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
