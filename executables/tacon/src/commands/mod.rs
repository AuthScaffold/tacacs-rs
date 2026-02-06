//! TACACS+ command implementations
//!
//! This module provides implementations for the three core TACACS+ operations:
//! - [`accounting`] - Record command execution and session events
//! - [`authentication`] - Verify user identity
//! - [`authorization`] - Check user permissions

pub mod accounting;
pub mod authentication;
pub mod authorization;
