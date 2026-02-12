//! REST API implementation

use axum::{
    routing::{get, post},
    Router,
};

/// Create REST API router
pub fn create_app() -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/v1/keys", post(create_key))
        .route("/v1/keys/:id/sign", post(sign))
}

async fn health_check() -> &'static str {
    "OK"
}

async fn create_key() -> &'static str {
    // TODO: Implement
    "Key created"
}

async fn sign() -> &'static str {
    // TODO: Implement
    "Signature"
}
