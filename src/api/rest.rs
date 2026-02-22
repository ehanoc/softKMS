//! REST API implementation
//!
//! This module provides the REST API for softKMS.
//! Token-based authentication only (no admin passphrase support).

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::api::auth::{self, extract_bearer_token};
use crate::identity::storage::IdentityStore;
use crate::key_service::KeyService;
use crate::{Config, KeyId, Result};

/// REST API server state
#[derive(Clone)]
pub struct RestState {
    pub key_service: Arc<KeyService>,
    pub identity_store: Arc<IdentityStore>,
    pub config: Config,
}

/// REST server
pub struct RestServer;

impl RestServer {
    /// Create a new REST server
    pub fn new() -> Self {
        Self
    }

    /// Start the REST server
    pub async fn start(
        &self,
        config: &Config,
        key_service: Arc<KeyService>,
        identity_store: Arc<IdentityStore>,
    ) -> Result<()> {
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
            key_service,
            identity_store,
        };

        let app = create_app().with_state(state);

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| crate::Error::Internal(format!("Failed to bind REST server: {}", e)))?;

        let local_addr = listener
            .local_addr()
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
        .route("/v1/status", get(status))
        .route("/v1/keys", get(list_keys).post(create_key))
        .route("/v1/keys/:id", get(get_key))
        .route("/v1/keys/:id/sign", post(sign))
        .route("/v1/keys/:id/verify", post(verify))
        .route("/v1/keys/:id/export/ssh", post(export_ssh))
        .route("/v1/keys/:id/export/gpg", post(export_gpg))
        .route("/v1/identities/me", get(get_identity))
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

/// Authenticate request using shared auth module
async fn authenticate(
    headers: &HeaderMap,
    state: &RestState,
) -> std::result::Result<String, (StatusCode, String)> {
    let token = extract_bearer_token(headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Authorization header required".to_string()))?;

    auth::authenticate(&token, &state.identity_store)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))
        .map(|user| user.identity_pubkey)
}

/// List keys endpoint
async fn list_keys(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> std::result::Result<Json<ListKeysResponse>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    // Use identity_pubkey as namespace - storage layer adds "/keys/" internally
    let keys = state
        .key_service
        .list_keys(Some(&identity_pubkey))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list keys: {}", e)))?;

    let key_infos: Vec<KeyInfo> = keys
        .into_iter()
        .map(|k| KeyInfo {
            key_id: k.id.to_string(),
            algorithm: k.algorithm,
            key_type: format!("{:?}", k.key_type),
            label: k.label,
            created_at: k.created_at.to_rfc3339(),
            public_key: if k.public_key.is_empty() {
                None
            } else {
                Some(BASE64.encode(&k.public_key))
            },
            owner_identity: k.owner_identity,
        })
        .collect();

    Ok(Json(ListKeysResponse { keys: key_infos }))
}

/// Get key endpoint
async fn get_key(
    Path(key_id): Path<String>,
    State(state): State<RestState>,
    headers: HeaderMap,
) -> std::result::Result<Json<KeyInfo>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    let key_uuid = KeyId::parse_str(&key_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key ID format".to_string()))?;

    let metadata = state
        .key_service
        .get_key(key_uuid)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get key: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Key not found".to_string()))?;

    // Check that the key belongs to the authenticated identity
    if metadata.owner_identity != Some(identity_pubkey.clone()) {
        return Err((StatusCode::FORBIDDEN, "Access denied to this key".to_string()));
    }

    Ok(Json(KeyInfo {
        key_id: metadata.id.to_string(),
        algorithm: metadata.algorithm.clone(),
        key_type: format!("{:?}", metadata.key_type),
        label: metadata.label.clone(),
        created_at: metadata.created_at.to_rfc3339(),
        public_key: if metadata.public_key.is_empty() {
            None
        } else {
            Some(BASE64.encode(&metadata.public_key))
        },
        owner_identity: metadata.owner_identity,
    }))
}

/// Create key endpoint
async fn create_key(
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(payload): Json<CreateKeyRequest>,
) -> std::result::Result<Json<CreateKeyResponse>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    // For identity-based operations, we need the master key to be cached
    // The key_service.sign/create uses cached master key for identity operations
    // But we need to ensure the keystore is initialized first
    
    let attributes = std::collections::HashMap::new();
    
    let metadata = state
        .key_service
        .create_key(
            payload.algorithm,
            payload.label,
            attributes,
            "", // Empty passphrase - uses cached master key for identity
            Some(identity_pubkey.clone()),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create key: {}", e)))?;

    Ok(Json(CreateKeyResponse {
        key_id: metadata.id.to_string(),
        algorithm: metadata.algorithm,
        public_key: if metadata.public_key.is_empty() {
            None
        } else {
            Some(BASE64.encode(&metadata.public_key))
        },
        created_at: metadata.created_at.to_rfc3339(),
        label: metadata.label,
    }))
}

/// Sign endpoint
async fn sign(
    Path(key_id): Path<String>,
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(payload): Json<SignRequest>,
) -> std::result::Result<Json<SignResponse>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    let key_uuid = KeyId::parse_str(&key_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key ID format".to_string()))?;

    let data = BASE64
        .decode(&payload.data)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64 data: {}", e)))?;

    let signature = state
        .key_service
        .sign(key_uuid, &data, "", Some(&identity_pubkey))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Signing failed: {}", e)))?;

    Ok(Json(SignResponse {
        key_id,
        signature: BASE64.encode(&signature.bytes),
        algorithm: signature.algorithm,
    }))
}

/// Verify endpoint
async fn verify(
    Path(key_id): Path<String>,
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyRequest>,
) -> std::result::Result<Json<VerifyResponse>, (StatusCode, String)> {
    // Authenticate but verification doesn't necessarily require ownership
    let _identity_pubkey = authenticate(&headers, &state).await.ok();

    let key_uuid = KeyId::parse_str(&key_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key ID format".to_string()))?;

    // Get key metadata to find algorithm
    let metadata = state
        .key_service
        .get_key(key_uuid)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get key: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Key not found".to_string()))?;

    let data = BASE64
        .decode(&payload.data)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64 data: {}", e)))?;

    let signature = BASE64
        .decode(&payload.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid base64 signature: {}", e)))?;

    // Verify based on algorithm
    // Note: This requires the public key to be stored - for stored keys, this is unimplemented
    let valid = if !metadata.public_key.is_empty() {
        match metadata.algorithm.as_str() {
            "ed25519" => {
                use crate::crypto::ed25519::Ed25519Engine;
                Ed25519Engine::verify(&metadata.public_key, &data, &signature).is_ok()
            }
            "p256" => {
                use crate::crypto::p256::DeterministicP256;
                DeterministicP256::verify(&metadata.public_key, &data, &signature).is_ok()
            }
            "falcon512" => {
                use crate::crypto::falcon::{FalconEngine, FalconVariant};
                let engine = FalconEngine::new(FalconVariant::Falcon512);
                engine.verify(&metadata.public_key, &data, &signature).unwrap_or(false)
            }
            "falcon1024" => {
                use crate::crypto::falcon::{FalconEngine, FalconVariant};
                let engine = FalconEngine::new(FalconVariant::Falcon1024);
                engine.verify(&metadata.public_key, &data, &signature).unwrap_or(false)
            }
            _ => false,
        }
    } else {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "Verify not implemented for stored keys without public key export".to_string(),
        ));
    };

    Ok(Json(VerifyResponse {
        valid,
        algorithm: metadata.algorithm,
    }))
}

/// Get identity endpoint - validates token and returns identity info
async fn get_identity(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> std::result::Result<Json<IdentityResponse>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    let identity = state
        .identity_store
        .load(&identity_pubkey)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load identity: {}", e)))?;

    Ok(Json(IdentityResponse {
        public_key: identity.public_key,
        key_type: identity.key_type.to_string(), // Use Display which returns kebab-case
        client_type: identity.client_type.to_string(), // Use Display which returns kebab-case
        description: identity.description,
        created_at: identity.created_at.to_rfc3339(),
        last_used: identity.last_used.to_rfc3339(),
        is_active: identity.is_active,
    }))
}

/// Start the REST API server
pub async fn start(
    config: &Config,
    key_service: Arc<KeyService>,
    identity_store: Arc<IdentityStore>,
) -> Result<()> {
    let server = RestServer::new();
    server.start(config, key_service, identity_store).await
}

// =============================================================================
// Response types
// =============================================================================

/// Status response
#[derive(Serialize)]
pub struct StatusResponse {
    version: String,
    grpc_addr: String,
    storage_backend: String,
}

/// Key info
#[derive(Serialize)]
pub struct KeyInfo {
    key_id: String,
    algorithm: String,
    key_type: String,
    label: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_identity: Option<String>,
}

/// List keys response
#[derive(Serialize)]
pub struct ListKeysResponse {
    keys: Vec<KeyInfo>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    created_at: String,
    label: Option<String>,
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
    algorithm: String,
}

/// Verify request
#[derive(Deserialize)]
pub struct VerifyRequest {
    data: String,
    signature: String,
}

/// Verify response
#[derive(Serialize)]
pub struct VerifyResponse {
    valid: bool,
    algorithm: String,
}

/// Identity response
#[derive(Serialize)]
pub struct IdentityResponse {
    public_key: String,
    key_type: String,
    client_type: String,
    description: Option<String>,
    created_at: String,
    last_used: String,
    is_active: bool,
}

/// Export SSH key request
#[derive(Deserialize)]
pub struct ExportSshRequest {
    pub passphrase: String,
    pub admin_passphrase: String,
    pub output_path: Option<String>,
}

/// Export SSH key response
#[derive(Serialize)]
pub struct ExportSshResponse {
    pub key_id: String,
    pub output_path: String,
    pub algorithm: String,
}

/// Export GPG key request
#[derive(Deserialize)]
pub struct ExportGpgRequest {
    pub admin_passphrase: String,
    pub user_id: Option<String>,
}

/// Export GPG key response
#[derive(Serialize)]
pub struct ExportGpgResponse {
    pub key_id: String,
    pub user_id: String,
    pub algorithm: String,
    pub armored_key: String,
}

/// Export SSH key endpoint
async fn export_ssh(
    Path(key_id): Path<String>,
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(payload): Json<ExportSshRequest>,
) -> std::result::Result<Json<ExportSshResponse>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    let key_uuid = KeyId::parse_str(&key_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key ID format".to_string()))?;

    // Get key to verify ownership
    let metadata = state
        .key_service
        .get_key(key_uuid)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get key: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Key not found".to_string()))?;

    // Check ownership (admin passphrase can override for testing)
    if metadata.owner_identity.is_some() && metadata.owner_identity != Some(identity_pubkey.clone()) {
        return Err((StatusCode::FORBIDDEN, "Access denied to this key".to_string()));
    }

    let output_path = state
        .key_service
        .export_ssh_key(
            key_uuid,
            &payload.passphrase,
            &payload.admin_passphrase,
            payload.output_path.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SSH export failed: {}", e)))?;

    Ok(Json(ExportSshResponse {
        key_id,
        output_path,
        algorithm: metadata.algorithm,
    }))
}

/// Export GPG key endpoint
async fn export_gpg(
    Path(key_id): Path<String>,
    State(state): State<RestState>,
    headers: HeaderMap,
    Json(payload): Json<ExportGpgRequest>,
) -> std::result::Result<Json<ExportGpgResponse>, (StatusCode, String)> {
    let identity_pubkey = authenticate(&headers, &state).await?;

    let key_uuid = KeyId::parse_str(&key_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid key ID format".to_string()))?;

    // Get key to verify ownership
    let metadata = state
        .key_service
        .get_key(key_uuid)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get key: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Key not found".to_string()))?;

    // Check ownership
    if metadata.owner_identity.is_some() && metadata.owner_identity != Some(identity_pubkey.clone()) {
        return Err((StatusCode::FORBIDDEN, "Access denied to this key".to_string()));
    }

    let (user_id, armored_key) = state
        .key_service
        .export_gpg_key(
            key_uuid,
            &payload.admin_passphrase,
            payload.user_id.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("GPG export failed: {}", e)))?;

    Ok(Json(ExportGpgResponse {
        key_id,
        user_id,
        algorithm: metadata.algorithm,
        armored_key,
    }))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rest_server_creation() {
        let server = RestServer::new();
        assert_eq!(std::mem::size_of_val(&server), 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        assert_eq!(response, "OK");
    }

    #[test]
    fn test_extract_bearer_token() {
        use axum::http::HeaderValue;
        let mut headers = HeaderMap::new();
        
        // No header
        assert!(extract_bearer_token(&headers).is_none());
        
        // With Bearer prefix
        headers.insert("authorization", HeaderValue::from_static("Bearer test-token"));
        assert_eq!(extract_bearer_token(&headers), Some("test-token".to_string()));
        
        // Without Bearer prefix
        headers.insert("authorization", HeaderValue::from_static("test-token-2"));
        assert_eq!(extract_bearer_token(&headers), Some("test-token-2".to_string()));
        
        // x-softkms-token fallback
        headers.clear();
        headers.insert("x-softkms-token", HeaderValue::from_static("fallback-token"));
        assert_eq!(extract_bearer_token(&headers), Some("fallback-token".to_string()));
    }
}
