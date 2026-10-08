//! Library surface for `sandbox-mint-server`: state, configuration, and
//! the transport-agnostic request/response dispatch functions in `api`.
//! No networking lives in this crate. Something else (a local IPC
//! mechanism, or nothing at all if wallet and mint share a process) is
//! responsible for actually moving bytes to and from these functions.

pub mod api;
pub mod config;
pub mod state;
