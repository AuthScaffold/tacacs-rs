#![doc = include_str!("../README.md")]

pub mod service;
pub mod upstream;

pub use service::{ServiceConfig, TacacsClientService};
pub use upstream::UpstreamConnectionOptions;
