#![doc = include_str!("../README.md")]

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
