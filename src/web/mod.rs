//! Web UI module for kubecontrol
//!
//! Provides an embedded web dashboard with:
//! - Live resource views
//! - Log streaming
//! - Web terminal (exec)
//! - YAML editor

pub mod assets;
pub mod server;
pub mod handlers;
pub mod websocket;

pub use server::start_server;
