mod common;
mod dedicated;
mod direct;
mod multiplexed;
#[cfg(target_os = "linux")]
mod service;

pub(crate) use direct::execute_batch;
#[cfg(target_os = "linux")]
pub(crate) use service::execute_batch_via_service;
