//! TACACS+ command implementations
//!
//! This module provides implementations for the three core TACACS+ operations:
//! - [`accounting`] - Record command runs and session events
//! - [`authentication`] - Authenticate a user
//! - [`authorization`] - Authorize a user action

pub mod accounting;
pub mod authentication;
pub mod authorization;
