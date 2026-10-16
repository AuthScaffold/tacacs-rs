#![doc = include_str!("../README.md")]

mod source;
mod resolver;

pub use source::{CrlFetchLimits, HttpCrlSource, HttpOcspSource};
pub use resolver::HttpCrlResolver;
