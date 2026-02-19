//! REST client for PKCS#11 provider
//!
//! This module provides a synchronous HTTP client to communicate with the softKMS daemon.
//! Uses reqwest::blocking for simplicity - no async runtime needed.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{error, info};

/// Result type for daemon operations
pub type DaemonResult<T> = Result<T, DaemonError>;

/// Daemon client errors
#[derive(Debug)]
pub enum DaemonError {
    /// Connection error
    Connection(String),

    /// HTTP error
    Http(String),

    /// Key not found
    KeyNotFound(String),

    /// Authentication error
    Auth(String),

    /// Operation not supported
    NotSupported(String),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::Connection(msg) => write!(f, "Connection: {}", msg),
            DaemonError::Http(msg) => write!(f, "HTTP: {}", msg),
            DaemonError::KeyNotFound(id) => write!(f, "Key not found: {}", id),
            DaemonError::Auth(msg) => write!(f, "Auth: {}", msg),
            DaemonError::NotSupported(msg) => write!(f, "Not supported: {}", msg),
        }
    }
}

impl std::error::Error for DaemonError {}

/// Key information from the daemon
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub id: String,
    pub label: String,
    pub algorithm: String,
    pub created_at: String,
    pub public_key: Option<String>,
}

/// REST request/response types
#[derive(Serialize)]
struct CreateKeyRequest {
    algorithm: String,
    label: String,
}

#[derive(Deserialize)]
struct CreateKeyResponse {
    key_id: String,
}

#[derive(Deserialize)]
struct ListKeysResponse {
    keys: Vec<KeyInfoResponse>,
}

#[derive(Deserialize)]
struct KeyInfoResponse {
    key_id: String,
    algorithm: String,
    label: Option<String>,
    created_at: String,
    public_key: Option<String>,
}

#[derive(Serialize)]
struct SignRequest {
    data: String,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

#[derive(Serialize)]
struct VerifyRequest {
    data: String,
    signature: String,
}

#[derive(Deserialize)]
struct VerifyResponse {
    valid: bool,
}

#[derive(Deserialize)]
struct IdentityResponse {
    public_key: String,
    #[serde(rename = "client_type")]
    client_type: String,
    description: Option<String>,
    is_active: bool,
}

/// Global HTTP client with connection pooling
static HTTP_CLIENT: Lazy<Mutex<reqwest::blocking::Client>> = Lazy::new(|| {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to create HTTP client");
    Mutex::new(client)
});

/// REST client wrapper
pub struct RestClient {
    server: String,
}

impl RestClient {
    /// Create a new REST client
    pub fn new(server: &str) -> Self {
        Self {
            server: server.to_string(),
        }
    }

    /// Get the base URL for the REST API
    fn base_url(&self) -> String {
        // Convert gRPC address format to REST URL
        // gRPC: 127.0.0.1:50051 -> REST: http://127.0.0.1:<rest_port>
        // For now, assume server address includes the REST port
        format!("http://{}", self.server)
    }

    /// Get the global HTTP client
    fn client(&self) -> DaemonResult<std::sync::MutexGuard<'static, reqwest::blocking::Client>> {
        HTTP_CLIENT
            .lock()
            .map_err(|_| DaemonError::Connection("Failed to lock HTTP client".to_string()))
    }

    /// Check if server is reachable
    pub fn check_health(&self) -> DaemonResult<bool> {
        let client = self.client()?;
        let url = format!("{}/health", self.base_url());

        match client.get(&url).send() {
            Ok(response) => Ok(response.status().is_success()),
            Err(e) => Err(DaemonError::Connection(e.to_string())),
        }
    }

    /// List all keys for an identity token
    pub fn list_keys_with_identity(&self, identity_token: &str) -> DaemonResult<Vec<KeyInfo>> {
        let client = self.client()?;
        let url = format!("{}/v1/keys", self.base_url());

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", identity_token))
            .send()
            .map_err(|e| DaemonError::Http(e.to_string()))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let body: ListKeysResponse = response
                    .json()
                    .map_err(|e| DaemonError::Http(format!("JSON parse error: {}", e)))?;

                Ok(body
                    .keys
                    .into_iter()
                    .map(|k| KeyInfo {
                        id: k.key_id,
                        label: k.label.unwrap_or_default(),
                        algorithm: k.algorithm,
                        created_at: k.created_at,
                        public_key: k.public_key,
                    })
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(DaemonError::Auth("Invalid identity token".to_string()))
            }
            status => Err(DaemonError::Http(format!("Unexpected status: {}", status))),
        }
    }

    /// Get key info
    pub fn get_key(&self, key_id: &str, identity_token: &str) -> DaemonResult<KeyInfo> {
        let client = self.client()?;
        let url = format!("{}/v1/keys/{}", self.base_url(), key_id);

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", identity_token))
            .send()
            .map_err(|e| DaemonError::Http(e.to_string()))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let k: KeyInfoResponse = response
                    .json()
                    .map_err(|e| DaemonError::Http(format!("JSON parse error: {}", e)))?;

                Ok(KeyInfo {
                    id: k.key_id,
                    label: k.label.unwrap_or_default(),
                    algorithm: k.algorithm,
                    created_at: k.created_at,
                    public_key: k.public_key,
                })
            }
            reqwest::StatusCode::NOT_FOUND => Err(DaemonError::KeyNotFound(key_id.to_string())),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(DaemonError::Auth("Invalid identity token".to_string()))
            }
            status => Err(DaemonError::Http(format!("Unexpected status: {}", status))),
        }
    }

    /// Sign data
    pub fn sign(&self, key_id: &str, data: &[u8], identity_token: &str) -> DaemonResult<Vec<u8>> {
        let client = self.client()?;
        let url = format!("{}/v1/keys/{}/sign", self.base_url(), key_id);

        let data_b64 = BASE64.encode(data);
        let request_body = SignRequest { data: data_b64 };

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", identity_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .map_err(|e| DaemonError::Http(e.to_string()))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let body: SignResponse = response
                    .json()
                    .map_err(|e| DaemonError::Http(format!("JSON parse error: {}", e)))?;

                BASE64
                    .decode(&body.signature)
                    .map_err(|e| DaemonError::Http(format!("Base64 decode error: {}", e)))
            }
            reqwest::StatusCode::NOT_FOUND => Err(DaemonError::KeyNotFound(key_id.to_string())),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(DaemonError::Auth("Invalid identity token".to_string()))
            }
            status => Err(DaemonError::Http(format!("Unexpected status: {}", status))),
        }
    }

    /// Verify a signature
    pub fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> DaemonResult<bool> {
        let client = self.client()?;
        let url = format!("{}/v1/keys/{}/verify", self.base_url(), key_id);

        let request_body = VerifyRequest {
            data: BASE64.encode(data),
            signature: BASE64.encode(signature),
        };

        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .map_err(|e| DaemonError::Http(e.to_string()))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let body: VerifyResponse = response
                    .json()
                    .map_err(|e| DaemonError::Http(format!("JSON parse error: {}", e)))?;
                Ok(body.valid)
            }
            reqwest::StatusCode::NOT_FOUND => Err(DaemonError::KeyNotFound(key_id.to_string())),
            status => Err(DaemonError::Http(format!("Unexpected status: {}", status))),
        }
    }

    /// Create/generate a new key
    pub fn create_key(
        &self,
        algorithm: &str,
        label: &str,
        identity_token: &str,
    ) -> DaemonResult<String> {
        let client = self.client()?;
        let url = format!("{}/v1/keys", self.base_url());

        let request_body = CreateKeyRequest {
            algorithm: algorithm.to_string(),
            label: label.to_string(),
        };

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", identity_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .map_err(|e| DaemonError::Http(e.to_string()))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let body: CreateKeyResponse = response
                    .json()
                    .map_err(|e| DaemonError::Http(format!("JSON parse error: {}", e)))?;
                Ok(body.key_id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(DaemonError::Auth("Invalid identity token".to_string()))
            }
            status => Err(DaemonError::Http(format!("Unexpected status: {}", status))),
        }
    }

    /// Validate an identity token and return (public_key, identity_info)
    pub fn validate_identity_token(&self, token: &str) -> DaemonResult<(String, String)> {
        let client = self.client()?;
        let url = format!("{}/v1/identities/me", self.base_url());

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .map_err(|e| DaemonError::Http(e.to_string()))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let body: IdentityResponse = response
                    .json()
                    .map_err(|e| DaemonError::Http(format!("JSON parse error: {}", e)))?;

                let info = format!("Identity: {}, Active: {}", body.client_type, body.is_active);

                Ok((body.public_key, info))
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(DaemonError::Auth("Invalid identity token".to_string()))
            }
            status => Err(DaemonError::Http(format!("Unexpected status: {}", status))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RestClient::new("127.0.0.1:50051");
        // Just verify it doesn't panic
        let _ = client.base_url();
    }
}
