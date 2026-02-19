//! Shared authentication logic for API servers
//!
//! This module provides common authentication/authorization functionality
//! used by both gRPC and REST API servers.

use crate::identity::storage::IdentityStore;
use crate::identity::validation::validate_token;
use crate::identity::types::{Identity, IdentityRole};

/// Result of successful authentication
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// Public key of the authenticated identity
    pub identity_pubkey: String,
    /// Whether this is an admin user (has admin role)
    pub is_admin: bool,
}

/// Extract bearer token from authorization header
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // Try with Bearer prefix
            if let Some(token) = v.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
            // No Bearer prefix - return as-is (for compatibility)
            Some(v.to_string())
        })
        .or_else(|| {
            // Fallback to x-softkms-token header
            headers
                .get("x-softkms-token")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
}

/// Authenticate using identity token and return identity public key
pub async fn authenticate_identity(
    token: &str,
    identity_store: &IdentityStore,
) -> Result<Identity, String> {
    validate_token(identity_store, token)
        .await
        .map_err(|e| format!("Invalid identity token: {}", e))
}

/// Authenticate request and extract identity public key
pub async fn authenticate(
    token: &str,
    identity_store: &IdentityStore,
) -> Result<AuthenticatedUser, String> {
    let identity = authenticate_identity(token, identity_store).await?;

    if !identity.is_active {
        return Err("Identity has been revoked".to_string());
    }

    Ok(AuthenticatedUser {
        identity_pubkey: identity.public_key.clone(),
        is_admin: identity.role == IdentityRole::Admin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_none());

        headers.insert(
            "authorization",
            "Bearer test-token-123".parse().unwrap(),
        );
        assert_eq!(extract_bearer_token(&headers), Some("test-token-123".to_string()));
    }
}
