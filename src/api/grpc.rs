//! gRPC API implementation
//!
//! This module provides the gRPC API for softKMS.

use crate::Config;
use crate::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

/// gRPC server handle
pub struct GrpcServer;

impl GrpcServer {
    /// Create a new gRPC server
    pub fn new() -> Self {
        Self
    }

    /// Start the gRPC server
    pub async fn start(&self, config: &Config) -> Result<()> {
        let addr: SocketAddr = config
            .api
            .grpc_addr
            .parse()
            .map_err(|e| crate::Error::InvalidParams(format!("Invalid gRPC address: {}", e)))?;

        info!("Starting gRPC server on {}", addr);

        // For now, just bind to the address to verify it's available
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| crate::Error::Internal(format!("Failed to bind gRPC server: {}", e)))?;

        let local_addr = listener.local_addr()
            .map_err(|e| crate::Error::Internal(format!("Failed to get local address: {}", e)))?;
        info!("gRPC server bound to {}", local_addr);

        // TODO: Implement actual gRPC service
        // For now, just keep the socket open
        tokio::spawn(async move {
            // Placeholder - actual gRPC implementation would go here
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }
}

impl Default for GrpcServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the gRPC API server
pub async fn start(config: &Config) -> Result<()> {
    let server = GrpcServer::new();
    server.start(config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_grpc_server_creation() {
        let server = GrpcServer::new();
        // Just verify it can be created
        assert_eq!(std::mem::size_of_val(&server), 0); // Zero-sized type
    }

    #[tokio::test]
    async fn test_grpc_server_start() {
        let mut config = Config::default();
        config.api.grpc_addr = "127.0.0.1:0".to_string(); // Random port

        let server = GrpcServer::new();
        let result = server.start(&config).await;
        
        // Should succeed in binding
        assert!(result.is_ok());
    }
}
