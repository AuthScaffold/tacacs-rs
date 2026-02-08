# Makefile for TACACS-rs FFI C Examples

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -I../../include
# Use absolute path for library directory  
LIB_DIR = /home/runner/work/tacacs-rs/tacacs-rs/target/release
LDFLAGS = $(LIB_DIR)/libtacacsrs.so -lpthread -ldl -lm

# Targets
TARGET = simple_example
SOURCE = simple_example.c

.PHONY: all clean run build-lib

all: build-lib $(TARGET)

# Build the Rust library first
build-lib:
	@echo "Building Rust FFI library..."
	@cd ../../../.. && cargo build --package tacacsrs-ffi --release

$(TARGET): $(SOURCE)
	@echo "Compiling C example..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)
	@echo "Build complete!"

run: $(TARGET)
	@echo "Running example..."
	LD_LIBRARY_PATH=$(LIB_DIR):$$LD_LIBRARY_PATH ./$(TARGET)

clean:
	rm -f $(TARGET)
	@echo "Cleaned build artifacts"

help:
	@echo "TACACS-rs FFI C Examples Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the Rust library and C example (default)"
	@echo "  build-lib - Build only the Rust library"
	@echo "  run       - Build and run the example"
	@echo "  clean     - Remove build artifacts"
	@echo "  help      - Show this help message"
