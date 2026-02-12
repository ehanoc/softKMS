//! API module - gRPC and REST implementations

pub mod grpc;
pub mod rest;

use crate::{Config, Result};

/// Start API servers
pub async fn start(_config: &Config) -> Result<()> {
    // TODO: Implement API server startup
    Ok(())
}
