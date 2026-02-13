//! REST API implementation
//!
//! This module provides the REST API for softKMS.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::Config;
use crate::Result;

/// REST API server state
#[derive(Clone)]
pub struct RestState {
    config: Config,
}

/// REST server
pub struct RestServer;

impl RestServer {
    /// Create a new REST server
    pub fn new() -> Self {
        Self
    }

    /// Start the REST server
    pub async fn start(&self, config: &Config) -> Result<()> {
        let addr_str = config
            .api
            .rest_addr
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidParams("REST API not configured".to_string()))?;

        let addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| crate::Error::InvalidParams(format!("Invalid REST address: {}", e)))?;

        info!("Starting REST server on {}", addr);

        let state = RestState {
            config: config.clone(),
        };

        let app = create_app().with_state(state);

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| crate::Error::Internal(format!("Failed to bind REST server: {}", e)))?;

        let local_addr = listener.local_addr()
            .map_err(|e| crate::Error::Internal(format!("Failed to get local address: {}", e)))?;
        info!("REST server bound to {}", local_addr);

        // Start server in background
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("REST server error: {}", e);
            }
        });

        Ok(())
    }
}

impl Default for RestServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Create REST API router
pub fn create_app() -> Router<RestState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/v1/keys", post(create_key))
        .route("/v1/keys/:id/sign", post(sign))
        .route("/v1/status", get(status))
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// API status endpoint
async fn status(State(state): State<RestState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        grpc_addr: state.config.api.grpc_addr.clone(),
        storage_backend: state.config.storage.backend.clone(),
    })
}

/// Create key endpoint
async fn create_key() -> std::result::Result<Json<CreateKeyResponse>, (StatusCode, String)> {
    // TODO: Implement actual key creation
    Ok(Json(CreateKeyResponse {
        key_id: "placeholder".to_string(),
        algorithm: "ed25519".to_string(),
    }))
}

/// Sign endpoint
async fn sign(Path(id): Path<String>) -> std::result::Result<Json<SignResponse>, (StatusCode, String)> {
    // TODO: Implement actual signing
    Ok(Json(SignResponse {
        key_id: id,
        signature: "placeholder".to_string(),
    }))
}

/// Start the REST API server
pub async fn start(config: &Config) -> Result<()> {
    let server = RestServer::new();
    server.start(config).await
}

/// Status response
#[derive(Serialize)]
pub struct StatusResponse {
    version: String,
    grpc_addr: String,
    storage_backend: String,
}

/// Create key request
#[derive(Deserialize)]
pub struct CreateKeyRequest {
    algorithm: String,
    label: Option<String>,
}

/// Create key response
#[derive(Serialize)]
pub struct CreateKeyResponse {
    key_id: String,
    algorithm: String,
}

/// Sign request
#[derive(Deserialize)]
pub struct SignRequest {
    data: String,
}

/// Sign response
#[derive(Serialize)]
pub struct SignResponse {
    key_id: String,
    signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rest_server_creation() {
        let server = RestServer::new();
        assert_eq!(std::mem::size_of_val(&server), 0); // Zero-sized type
    }

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response, "OK");
    }
}
