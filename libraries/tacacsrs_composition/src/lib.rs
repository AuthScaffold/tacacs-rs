#![doc = include_str!("../README.md")]

mod checks;
mod component;
mod composition;
mod deferred;
mod graph;
mod registry;
#[cfg(test)]
mod tests;

pub use component::{check_names, prepare_all, register_all, Component, Value};
pub use composition::{Composition, Named};
pub use graph::Graph;
