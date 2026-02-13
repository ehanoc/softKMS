//! API module - gRPC and REST implementations

pub mod grpc;
pub mod rest;

/// Generated protobuf code
/// Re-exported for use by the gRPC server and other modules
pub mod softkms {
    include!("softkms.rs");
}

use crate::{Config, Result};

/// Start API servers
pub async fn start(_config: &Config) -> Result<()> {
    // TODO: Implement API server startup
    Ok(())
}
