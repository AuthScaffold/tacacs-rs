#![doc = include_str!("../README.md")]

mod client;
pub mod controller;
mod emulator;
mod protocol;
mod scenario;
mod service;
mod state;

#[cfg(test)]
mod tests;

pub use client::MockControllerClient;
pub use emulator::IpcEmulator;
pub use scenario::{
    CapturedIpcRequest, EmulatorResponse, EmulatorScenario, ErrorBody, IpcRpc, MatchFields,
    ResponseBody, RuleHitCount, ScenarioAuthorizationArg, TransactionRule,
};
