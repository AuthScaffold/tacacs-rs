# FFI Integration Guide

This guide provides comprehensive instructions for integrating TACACS-rs with C and C++ applications through the Foreign Function Interface (FFI).

## Table of Contents

1. [Quick Start](#quick-start)
2. [Library Architecture](#library-architecture)
3. [Building](#building)
4. [Integration Methods](#integration-methods)
5. [API Overview](#api-overview)
6. [Memory Management](#memory-management)
7. [Error Handling](#error-handling)
8. [Best Practices](#best-practices)
9. [Platform-Specific Notes](#platform-specific-notes)
10. [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Build the FFI Library

```bash
cd /path/to/tacacs-rs
cargo build --package tacacsrs-ffi --release
```

This generates:
- Dynamic library: `target/release/libtacacsrs.so` (Linux)
- Static library: `target/release/libtacacsrs.a`
- C header: `libraries/tacacsrs_ffi/include/tacacs.h`

### 2. Run the Example

```bash
cd libraries/tacacsrs_ffi/examples/c
make run
```

## Library Architecture

The FFI layer consists of three main components:

```
┌─────────────────────────────────────┐
│   C/C++ Application                 │
└─────────────────┬───────────────────┘
                  │
                  ├─ #include "tacacs.h"
                  │
┌─────────────────▼───────────────────┐
│   FFI Layer (tacacsrs-ffi)         │
│   - Opaque types                    │
│   - C-compatible functions          │
│   - Memory management               │
│   - Error handling                  │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   Rust Core Libraries               │
│   - tacacsrs-messages               │
│   - tacacsrs-networking             │
└─────────────────────────────────────┘
```

## Building

### Prerequisites

- **Rust**: 1.70 or later
- **C Compiler**: gcc, clang, or MSVC
- **C++ Compiler**: g++, clang++ (for C++ examples)
- **Build Tools**: make, cmake (optional)

### Build Commands

```bash
# Debug build (faster compilation, slower runtime)
cargo build --package tacacsrs-ffi

# Release build (optimized, recommended for production)
cargo build --package tacacsrs-ffi --release

# With all features
cargo build --package tacacsrs-ffi --release --all-features
```

### Verifying the Build

```bash
# Check dynamic library
file target/release/libtacacsrs.so
# Expected: ELF 64-bit LSB shared object

# Check static library
ar -t target/release/libtacacsrs.a | head -5

# Check symbols
nm -D target/release/libtacacsrs.so | grep tacacs_
```

## Integration Methods

### Method 1: Direct Linking (Recommended)

```makefile
CC = gcc
CFLAGS = -I/path/to/tacacsrs-ffi/include
LDFLAGS = /path/to/target/release/libtacacsrs.so -lpthread -ldl -lm

myapp: myapp.c
\t$(CC) $(CFLAGS) -o myapp myapp.c $(LDFLAGS)
```

### Method 2: Using -L and -l

```makefile
LDFLAGS = -L/path/to/target/release -ltacacsrs -lpthread -ldl -lm
```

Note: Requires setting `LD_LIBRARY_PATH` at runtime.

### Method 3: CMake Integration

See `libraries/tacacsrs_ffi/examples/c/CMakeLists.txt` for a complete example.

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyTacacsApp C)

include_directories(/path/to/include)
link_directories(/path/to/target/release)

add_executable(myapp myapp.c)
target_link_libraries(myapp tacacsrs pthread dl m)
```

## API Overview

### Core Concepts

1. **Opaque Pointers**: Rust objects are accessed through opaque C pointers
2. **Ownership**: Objects created with `_new()` must be freed with `_free()`
3. **Error Handling**: Most functions accept a `tacacs_TacacsError*` parameter
4. **Null Safety**: All functions handle NULL pointers gracefully

### Available Functions

#### Header Operations

```c
// Create a new header
tacacs_TacacsHeader* tacacs_header_new(
    tacacs_CTacacsMajorVersion major_version,
    tacacs_CTacacsMinorVersion minor_version,
    tacacs_CTacacsType tacacs_type,
    uint8_t seq_no,
    uint8_t flags,
    uint32_t session_id,
    uint32_t length,
    tacacs_TacacsError* error
);

// Parse header from bytes
tacacs_TacacsHeader* tacacs_header_from_bytes(
    const uint8_t* data,
    size_t data_len,
    tacacs_TacacsError* error
);

// Serialize header to bytes
size_t tacacs_header_to_bytes(
    const tacacs_TacacsHeader* header,
    uint8_t* buffer,
    size_t buffer_len,
    tacacs_TacacsError* error
);

// Getters
uint32_t tacacs_header_get_session_id(const tacacs_TacacsHeader* header);
uint8_t tacacs_header_get_seq_no(const tacacs_TacacsHeader* header);
uint32_t tacacs_header_get_length(const tacacs_TacacsHeader* header);

// Free
void tacacs_header_free(tacacs_TacacsHeader* header);
```

#### Packet Operations

```c
// Create a new packet
tacacs_TacacsPacket* tacacs_packet_new(
    const tacacs_TacacsHeader* header,
    const uint8_t* body,
    size_t body_len,
    tacacs_TacacsError* error
);

// Parse packet from bytes
tacacs_TacacsPacket* tacacs_packet_from_bytes(
    const uint8_t* data,
    size_t data_len,
    tacacs_TacacsError* error
);

// Serialize packet to bytes (returns allocated buffer)
uint8_t* tacacs_packet_to_bytes(
    const tacacs_TacacsPacket* packet,
    size_t* out_len,
    tacacs_TacacsError* error
);

// Obfuscate/Deobfuscate
tacacs_TacacsPacket* tacacs_packet_obfuscate(
    const tacacs_TacacsPacket* packet,
    const uint8_t* key,
    size_t key_len,
    tacacs_TacacsError* error
);

tacacs_TacacsPacket* tacacs_packet_deobfuscate(
    const tacacs_TacacsPacket* packet,
    const uint8_t* key,
    size_t key_len,
    tacacs_TacacsError* error
);

// Free
void tacacs_packet_free(tacacs_TacacsPacket* packet);
void tacacs_free_bytes(uint8_t* buffer);
```

## Memory Management

### Ownership Rules

1. **Creation**: Functions ending in `_new()` or returning pointers create owned objects
2. **Destruction**: Functions ending in `_free()` destroy owned objects
3. **Borrowed References**: `const` pointers are borrowed (do not free)
4. **Allocated Buffers**: Buffers from `_to_bytes()` must be freed with `tacacs_free_bytes()`

### Example: Complete Lifecycle

```c
void example_lifecycle(void) {
    tacacs_TacacsError error;
    
    // 1. Create header (ownership acquired)
    tacacs_TacacsHeader* header = tacacs_header_new(..., &error);
    if (!header) {
        // Handle error
        tacacs_free_error_message(error.message);
        return;
    }
    
    // 2. Use header (borrowed reference passed to packet_new)
    tacacs_TacacsPacket* packet = tacacs_packet_new(header, body, len, &error);
    if (!packet) {
        tacacs_free_error_message(error.message);
        tacacs_header_free(header);  // Still need to free header
        return;
    }
    
    // 3. Serialize (new buffer allocated)
    size_t out_len;
    uint8_t* bytes = tacacs_packet_to_bytes(packet, &out_len, &error);
    if (!bytes) {
        tacacs_free_error_message(error.message);
        tacacs_packet_free(packet);
        tacacs_header_free(header);
        return;
    }
    
    // 4. Use bytes
    // ... do something with bytes ...
    
    // 5. Clean up (in reverse order of allocation)
    tacacs_free_bytes(bytes);
    tacacs_packet_free(packet);
    tacacs_header_free(header);
}
```

### C++ RAII Pattern

For C++, use RAII wrappers for automatic cleanup:

```cpp
template<typename T, void(*Deleter)(T*)>
class UniquePtr {
    T* ptr_;
public:
    explicit UniquePtr(T* p) : ptr_(p) {}
    ~UniquePtr() { if (ptr_) Deleter(ptr_); }
    T* get() const { return ptr_; }
    T* release() { T* p = ptr_; ptr_ = nullptr; return p; }
private:
    UniquePtr(const UniquePtr&) = delete;
    UniquePtr& operator=(const UniquePtr&) = delete;
};

using HeaderPtr = UniquePtr<tacacs_TacacsHeader, tacacs_header_free>;
using PacketPtr = UniquePtr<tacacs_TacacsPacket, tacacs_packet_free>;
```

## Error Handling

### Error Structure

```c
typedef enum {
    TACACS_TACACS_RESULT_SUCCESS = 0,
    TACACS_TACACS_RESULT_INVALID_INPUT = 1,
    TACACS_TACACS_RESULT_NETWORK_FAILURE = 2,
    TACACS_TACACS_RESULT_PROTOCOL_ERROR = 3,
    TACACS_TACACS_RESULT_MEMORY_ALLOCATION = 4,
    TACACS_TACACS_RESULT_NULL_POINTER = 5,
    TACACS_TACACS_RESULT_INVALID_UTF8 = 6,
    TACACS_TACACS_RESULT_BUFFER_TOO_SMALL = 7,
    TACACS_TACACS_RESULT_INVALID_HEADER = 8,
    TACACS_TACACS_RESULT_INVALID_PACKET = 9,
    TACACS_TACACS_RESULT_UNKNOWN = 255
} tacacs_TacacsResult;

typedef struct {
    tacacs_TacacsResult code;
    char* message;  // Allocated string, must be freed
} tacacs_TacacsError;
```

### Error Handling Pattern

```c
tacacs_TacacsError error;
tacacs_TacacsHeader* header = tacacs_header_new(..., &error);

if (header == NULL) {
    // Error occurred
    fprintf(stderr, "Error code %d: %s\n", error.code, error.message);
    
    // Always free the error message
    tacacs_free_error_message(error.message);
    
    // Handle error appropriately
    return -1;
}

// Success case
// ... use header ...

tacacs_header_free(header);
```

## Best Practices

### 1. Always Check Return Values

```c
// BAD: Ignoring NULL return
tacacs_TacacsHeader* header = tacacs_header_new(..., &error);
uint32_t sid = tacacs_header_get_session_id(header);  // May crash!

// GOOD: Check before use
tacacs_TacacsHeader* header = tacacs_header_new(..., &error);
if (header) {
    uint32_t sid = tacacs_header_get_session_id(header);
    // ... use sid ...
    tacacs_header_free(header);
} else {
    // Handle error
}
```

### 2. Free Error Messages

```c
// Always free error messages, even on success
tacacs_TacacsError error;
tacacs_TacacsHeader* header = tacacs_header_new(..., &error);
if (!header && error.message) {
    fprintf(stderr, "%s\n", error.message);
    tacacs_free_error_message(error.message);  // Important!
}
```

### 3. Use Stack-Allocated Error Structs

```c
// GOOD: Stack allocation
tacacs_TacacsError error;
tacacs_header_new(..., &error);

// Avoid: Heap allocation is unnecessary
tacacs_TacacsError* error = malloc(sizeof(tacacs_TacacsError));
```

### 4. Match Allocation with Deallocation

```c
// Each _new() must have a corresponding _free()
tacacs_TacacsHeader* h = tacacs_header_new(...);
// ... use h ...
tacacs_header_free(h);  // Required

// Each _to_bytes() must have tacacs_free_bytes()
uint8_t* bytes = tacacs_packet_to_bytes(...);
// ... use bytes ...
tacacs_free_bytes(bytes);  // Required
```

## Platform-Specific Notes

### Linux

```bash
# Library location
export LD_LIBRARY_PATH=/path/to/target/release:$LD_LIBRARY_PATH

# Or install system-wide
sudo cp target/release/libtacacsrs.so /usr/local/lib/
sudo cp libraries/tacacsrs_ffi/include/tacacs.h /usr/local/include/
sudo ldconfig
```

### macOS

```bash
# Library location
export DYLD_LIBRARY_PATH=/path/to/target/release:$DYLD_LIBRARY_PATH

# Or install system-wide
sudo cp target/release/libtacacsrs.dylib /usr/local/lib/
sudo cp libraries/tacacsrs_ffi/include/tacacs.h /usr/local/include/
```

### Windows

```powershell
# Add to PATH or copy to same directory as executable
copy target\release\tacacsrs.dll .
copy libraries\tacacsrs_ffi\include\tacacs.h .
```

## Troubleshooting

### Problem: "cannot find -ltacacsrs"

**Solution**: Linker can't find the library.

```bash
# Option 1: Use full path
gcc myapp.c /path/to/libtacacsrs.so ...

# Option 2: Add to library path
export LD_LIBRARY_PATH=/path/to/target/release:$LD_LIBRARY_PATH
gcc myapp.c -L/path/to/target/release -ltacacsrs ...
```

### Problem: "error while loading shared libraries"

**Solution**: Runtime linker can't find the library.

```bash
# Temporary fix
LD_LIBRARY_PATH=/path/to/target/release ./myapp

# Permanent fix: Set RPATH during compilation
gcc -Wl,-rpath,/path/to/target/release myapp.c ...
```

### Problem: "undefined reference to tacacs_*"

**Solution**: Link order matters.

```bash
# WRONG: Library before object file
gcc -ltacacsrs myapp.c

# CORRECT: Library after object file
gcc myapp.c -ltacacsrs
```

### Problem: Segmentation fault

**Causes**:
1. Using NULL pointer without checking
2. Using freed pointer (use-after-free)
3. Double-free
4. Buffer overflow

**Debug**:
```bash
# Use Valgrind
valgrind --leak-check=full ./myapp

# Use AddressSanitizer
gcc -fsanitize=address myapp.c ...
./myapp
```

## Further Reading

- [Rust FFI Omnibus](https://jakegoulding.com/rust-ffi-omnibus/)
- [RFC 8907 - TACACS+ Protocol](https://tools.ietf.org/rfc/rfc8907.txt)
- [Generated C Header](../include/tacacs.h)
- [C Example](../examples/c/simple_example.c)
- [C++ Example](../examples/cpp/simple_example.cpp)
