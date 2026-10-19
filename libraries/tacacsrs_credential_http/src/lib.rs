#![doc = include_str!("../README.md")]

mod source;
mod resolver;

pub use source::{EvidenceFetchLimits, HttpCrlSource, HttpOcspSource};
pub use resolver::HttpEvidenceResolver;
