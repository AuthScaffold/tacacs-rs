# TACACS-rs FFI Library

Foreign Function Interface (FFI) bindings for the TACACS-rs library, enabling C and C++ applications to use the TACACS+ protocol implementation.

## Overview

The `tacacsrs-ffi` crate provides a C-compatible API for the TACACS-rs library, allowing integration with:
- C applications
- C++ applications
- Any language with C FFI support (Python via ctypes, Java via JNI, etc.)

## Features

- **Dynamic and Static Libraries**: Builds as both `.so`/`.dylib`/`.dll` (dynamic) and `.a` (static)
- **Automatic Header Generation**: C header files generated via cbindgen
- **Memory Safe**: Proper resource management across FFI boundary
- **Comprehensive Error Handling**: C-style error codes and messages
- **Cross-Platform**: Supports Linux, macOS, and Windows
- **Well Documented**: Complete C/C++ examples and API documentation

## Building

### Prerequisites

- Rust 1.70 or later
- C compiler (gcc, clang, or MSVC)
- C++ compiler (for C++ examples)

### Build the Library

```bash
# Debug build
cargo build --package tacacsrs-ffi

# Release build (recommended for production)
cargo build --package tacacsrs-ffi --release
```

The build produces:
- **Dynamic library**: `target/release/libtacacsrs.so` (Linux), `libtacacsrs.dylib` (macOS), `tacacsrs.dll` (Windows)
- **Static library**: `target/release/libtacacsrs.a`
- **C header**: `include/tacacs.h`

## Usage

### C Example

```c
#include "tacacs.h"
#include <stdio.h>

int main(void) {
    tacacs_TacacsError error;
    
    // Create a TACACS+ header
    tacacs_TacacsHeader* header = tacacs_header_new(
        TACACS_C_TACACS_MAJOR_VERSION_TACACS_PLUS_MAJOR1,
        TACACS_C_TACACS_MINOR_VERSION_TACACS_PLUS_MINOR_VER_ONE,
        TACACS_C_TACACS_TYPE_TAC_PLUS_AUTHENTICATION,
        1,                              // seq_no
        tacacs_TACACS_FLAG_UNENCRYPTED, // flags
        12345,                          // session_id
        11,                             // length
        &error
    );
    
    if (header == NULL) {
        fprintf(stderr, "Error: %s\n", error.message);
        tacacs_free_error_message(error.message);
        return 1;
    }
    
    // Create packet body
    const char* body = "Hello TACACS";
    tacacs_TacacsPacket* packet = tacacs_packet_new(
        header,
        (const uint8_t*)body,
        strlen(body),
        &error
    );
    
    // Serialize to bytes
    size_t len;
    uint8_t* bytes = tacacs_packet_to_bytes(packet, &len, &error);
    
    // Clean up
    tacacs_free_bytes(bytes);
    tacacs_packet_free(packet);
    tacacs_header_free(header);
    
    return 0;
}
```

### C++ Example (with RAII)

```cpp
#include "tacacs.h"
#include <iostream>
#include <memory>

// RAII wrapper for automatic resource management
class TacacsHeaderWrapper {
public:
    explicit TacacsHeaderWrapper(tacacs_TacacsHeader* header) : header_(header) {}
    ~TacacsHeaderWrapper() { if (header_) tacacs_header_free(header_); }
    
    // Prevent copying, allow moving
    TacacsHeaderWrapper(const TacacsHeaderWrapper&) = delete;
    TacacsHeaderWrapper(TacacsHeaderWrapper&& other) noexcept 
        : header_(other.header_) { other.header_ = nullptr; }
    
    tacacs_TacacsHeader* get() const { return header_; }
private:
    tacacs_TacacsHeader* header_;
};

int main() {
    tacacs_TacacsError error;
    
    // Create header with automatic cleanup
    tacacs_TacacsHeader* raw_header = tacacs_header_new(
        TACACS_C_TACACS_MAJOR_VERSION_TACACS_PLUS_MAJOR1,
        TACACS_C_TACACS_MINOR_VERSION_TACACS_PLUS_MINOR_VER_ONE,
        TACACS_C_TACACS_TYPE_TAC_PLUS_AUTHENTICATION,
        1, tacacs_TACACS_FLAG_UNENCRYPTED, 12345, 11, &error
    );
    
    if (!raw_header) {
        std::cerr << "Error: " << error.message << std::endl;
        tacacs_free_error_message(error.message);
        return 1;
    }
    
    TacacsHeaderWrapper header(raw_header);
    // Automatic cleanup on scope exit
    
    return 0;
}
```

## Building Your Application

### Using Makefile

```makefile
CC = gcc
CFLAGS = -I/path/to/tacacsrs-ffi/include
LDFLAGS = -L/path/to/target/release -ltacacsrs -lpthread -ldl -lm

myapp: myapp.c
\t$(CC) $(CFLAGS) -o myapp myapp.c $(LDFLAGS)

run: myapp
\tLD_LIBRARY_PATH=/path/to/target/release ./myapp
```

### Using CMake

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyTacacsApp C)

# Find the library
set(TACACS_INCLUDE_DIR "/path/to/tacacsrs-ffi/include")
set(TACACS_LIBRARY_DIR "/path/to/target/release")

include_directories(${TACACS_INCLUDE_DIR})
link_directories(${TACACS_LIBRARY_DIR})

add_executable(myapp myapp.c)
target_link_libraries(myapp tacacsrs pthread dl m)

# Set RPATH for runtime
set_target_properties(myapp PROPERTIES
    INSTALL_RPATH "${TACACS_LIBRARY_DIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)
```

### Using pkg-config (future)

```bash
gcc myapp.c -o myapp $(pkg-config --cflags --libs tacacsrs)
```

## Examples

Complete working examples are provided in the `examples/` directory:

- **C Example**: `examples/c/simple_example.c` - Basic TACACS+ packet creation
- **C++ Example**: `examples/cpp/simple_example.cpp` - RAII-based resource management

Build and run:

```bash
# C example
cd examples/c
make run

# C++ example  
cd examples/cpp
make run
```

## API Reference

### Error Handling

```c
typedef enum {
    TACACS_TACACS_RESULT_SUCCESS = 0,
    TACACS_TACACS_RESULT_INVALID_INPUT = 1,
    TACACS_TACACS_RESULT_NETWORK_FAILURE = 2,
    TACACS_TACACS_RESULT_PROTOCOL_ERROR = 3,
    TACACS_TACACS_RESULT_MEMORY_ALLOCATION = 4,
    // ...
} tacacs_TacacsResult;

typedef struct {
    tacacs_TacacsResult code;
    char* message;  // Must be freed with tacacs_free_error_message()
} tacacs_TacacsError;
```

### Header Operations

- `tacacs_header_new()` - Create a new TACACS+ header
- `tacacs_header_from_bytes()` - Parse header from bytes
- `tacacs_header_to_bytes()` - Serialize header to bytes
- `tacacs_header_get_session_id()` - Get session ID
- `tacacs_header_get_seq_no()` - Get sequence number
- `tacacs_header_free()` - Free header memory

### Packet Operations

- `tacacs_packet_new()` - Create a new TACACS+ packet
- `tacacs_packet_from_bytes()` - Parse packet from bytes
- `tacacs_packet_to_bytes()` - Serialize packet to bytes
- `tacacs_packet_obfuscate()` - Obfuscate packet with key
- `tacacs_packet_deobfuscate()` - Deobfuscate packet with key
- `tacacs_packet_free()` - Free packet memory

### Memory Management

All allocated resources must be freed using the corresponding `_free()` functions:

```c
// Free functions
void tacacs_header_free(tacacs_TacacsHeader* header);
void tacacs_packet_free(tacacs_TacacsPacket* packet);
void tacacs_free_bytes(uint8_t* buffer);
void tacacs_free_string(char* str);
void tacacs_free_error_message(char* message);
```

## Memory Safety

The FFI layer implements proper memory management:

- **Opaque Pointers**: Rust objects are hidden behind opaque C pointers
- **Explicit Ownership**: Each `_new()` function creates owned objects
- **Explicit Cleanup**: Each `_free()` function deallocates resources
- **No Use-After-Free**: After calling `_free()`, pointers are invalid
- **No Double-Free**: Calling `_free()` on NULL is safe

## Thread Safety

Functions are thread-safe for:
- Creating independent objects (headers, packets)
- Reading from const pointers
- Freeing objects (with proper synchronization)

Note: Shared mutable access requires external synchronization.

## Platform Support

| Platform | Dynamic Library | Static Library | Tested |
|----------|----------------|----------------|---------|
| Linux    | ✓ `.so`        | ✓ `.a`         | ✓       |
| macOS    | ✓ `.dylib`     | ✓ `.a`         | -       |
| Windows  | ✓ `.dll`       | ✓ `.lib`       | -       |

## Troubleshooting

### Library Not Found

If you get "cannot find -ltacacsrs":

```bash
# Linux/macOS: Add to LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/target/release:$LD_LIBRARY_PATH

# macOS: Or use DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=/path/to/target/release:$DYLD_LIBRARY_PATH

# Or install to system
sudo cp target/release/libtacacsrs.so /usr/local/lib/
sudo ldconfig  # Linux only
```

### Header Not Found

```bash
# Add include path
gcc -I/path/to/tacacsrs-ffi/include ...
```

## Testing

Run the test suite:

```bash
cargo test --package tacacsrs-ffi
```

## License

MIT - See LICENSE file for details

## Contributing

Contributions welcome! Please ensure:
- FFI functions are documented
- Memory management is correct
- Examples are updated
- Tests pass

## Related Documentation

- [The Rust FFI Omnibus](https://jakegoulding.com/rust-ffi-omnibus/)
- [RFC 8907 - TACACS+ Protocol](https://tools.ietf.org/rfc/rfc8907.txt)
- [cbindgen Documentation](https://github.com/eqrion/cbindgen)
