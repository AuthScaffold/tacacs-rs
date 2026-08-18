#![doc = include_str!("../README.md")]

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("tacacsrs-agent-ipc-emulator supports Linux GNU only");

mod client;
pub mod controller;
mod emulator;
mod policy;
mod protocol;
mod service;
mod state;

#[cfg(test)]
mod tests;

pub use client::MockControllerClient;
pub use emulator::IpcEmulator;
pub use policy::{
    AuthorizationResponseArg, CapturedIpcRequest, EmulatorPolicy, EmulatorResponse, ErrorBody,
    IpcRpc, PolicyDecision, ResponseBody, DECISION_QUERY,
};
