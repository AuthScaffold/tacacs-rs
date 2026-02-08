cmake_minimum_required(VERSION 3.10)
project(TacacsFFIExample C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add warning flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# Find the TACACS-rs library
# For development, we use a relative path to the debug build
set(TACACS_LIBRARY_DIR "${CMAKE_SOURCE_DIR}/../../../target/debug")
set(TACACS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../../include")

# Add the include directory
include_directories(${TACACS_INCLUDE_DIR})

# Link directories
link_directories(${TACACS_LIBRARY_DIR})

# Add executable
add_executable(simple_example simple_example.c)

# Link libraries
target_link_libraries(simple_example tacacsrs pthread dl m)

# Custom target to build the Rust library
add_custom_target(build_rust_lib
    COMMAND cargo build --package tacacsrs-ffi
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../../..
    COMMENT "Building Rust FFI library..."
)

# Make the example depend on the Rust library
add_dependencies(simple_example build_rust_lib)

# Set RPATH for runtime library discovery
set_target_properties(simple_example PROPERTIES
    INSTALL_RPATH "${TACACS_LIBRARY_DIR}"
    BUILD_WITH_INSTALL_RPATH TRUE
)

# Installation rules
install(TARGETS simple_example DESTINATION bin)

# Print configuration info
message(STATUS "TACACS-rs FFI Example Configuration:")
message(STATUS "  Include directory: ${TACACS_INCLUDE_DIR}")
message(STATUS "  Library directory: ${TACACS_LIBRARY_DIR}")
