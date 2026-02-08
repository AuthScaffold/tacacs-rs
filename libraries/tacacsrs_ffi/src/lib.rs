//! TACACS-rs FFI Layer
//!
//! This crate provides Foreign Function Interface (FFI) bindings for the TACACS-rs library,
//! enabling C and C++ applications to use the TACACS+ protocol implementation.
//!
//! # Safety
//!
//! All public functions in this crate are marked as `unsafe` or contain `unsafe` blocks
//! because they cross the FFI boundary. Callers must ensure:
//! - Pointers are valid and properly aligned
//! - Pointers are not null (unless explicitly documented as nullable)
//! - String pointers point to valid null-terminated UTF-8
//! - Memory is freed using the corresponding `_free` functions

mod error;
mod header;
mod packet;
mod string_utils;

pub use error::*;
pub use header::*;
pub use packet::*;
pub use string_utils::*;
