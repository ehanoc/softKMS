//! gRPC authentication and authorization interceptor
//!
//! This module handles authentication for all gRPC requests.
//! Supports both identity tokens (clients) and admin passphrases.

use tonic::{Request, Status};
use crate::identity::storage::IdentityStore;
use crate::identity::types::{Identity, IdentityRole};
use crate::identity::validation::validate_token;
use crate::security::SecurityManager;
use std::sync::Arc;

/// Authentication context extracted from request
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub identity: Option<Identity>,
    pub is_admin: bool,
}

impl AuthContext {
    /// Create admin context (from passphrase auth)
    pub fn admin() -> Self {
        Self {
            identity: None,
            is_admin: true,
        }
    }

    /// Create client context (from token auth)
    pub fn client(identity: Identity) -> Self {
        Self {
            is_admin: identity.role == IdentityRole::Admin,
            identity: Some(identity),
        }
    }

    /// Get the identity public key if available
    pub fn identity_pubkey(&self) -> Option<&str> {
        self.identity.as_ref().map(|i| i.public_key.as_str())
    }
}

/// Extract auth_token from request metadata
pub fn extract_auth_token<T>(request: &Request<T>) -> Option<String> {
    // Check for auth_token in metadata header
    request.metadata()
        .get("auth_token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Validate identity token
async fn validate_identity_token(
    token: &str,
    identity_store: &IdentityStore,
) -> Result<AuthContext, Status> {
    match validate_token(identity_store, token).await {
        Ok(identity) => {
            if !identity.is_active {
                return Err(Status::permission_denied(
                    "Identity has been revoked"
                ));
            }
            Ok(AuthContext::client(identity))
        }
        Err(_) => Err(Status::permission_denied("Invalid identity token")),
    }
}

/// Validate admin passphrase
fn validate_admin_passphrase(
    passphrase: &str,
    security_manager: &SecurityManager,
) -> Result<AuthContext, Status> {
    match security_manager.verify_passphrase(passphrase) {
        Ok(true) => Ok(AuthContext::admin()),
        Ok(false) => Err(Status::permission_denied("Invalid admin passphrase")),
        Err(_) => Err(Status::internal("Authentication error")),
    }
}

/// Validate authentication from request
/// 
/// Priority:
/// 1. If auth_token provided -> validate as identity token
/// 2. If passphrase provided -> validate as admin passphrase
/// 3. If neither -> return unauthenticated error
pub async fn validate_auth(
    auth_token: Option<String>,
    passphrase: Option<String>,
    identity_store: &IdentityStore,
    security_manager: &SecurityManager,
) -> Result<AuthContext, Status> {
    // Validate identity token first
    if let Some(token) = auth_token {
        if !token.is_empty() {
            return validate_identity_token(&token, identity_store).await;
        }
    }
    
    // Validate admin passphrase
    if let Some(pass) = passphrase {
        if !pass.is_empty() {
            return validate_admin_passphrase(&pass, security_manager);
        }
    }
    
    Err(Status::unauthenticated("No authentication provided"))
}

/// Extract authentication from request and validate
/// 
/// This is the main entry point for handlers
pub async fn extract_and_validate_auth<T>(
    request: &Request<T>,
    identity_store: &IdentityStore,
    security_manager: &SecurityManager,
) -> Result<AuthContext, Status> {
    // Extract auth_token from metadata header
    let auth_token = extract_auth_token(request);
    
    // For now, we can't extract passphrase from request body here (need typed request)
    // The passphrase will be extracted in the handler from the request body
    // This is a limitation - token auth is preferred for identity operations
    
    // If we have a token, validate it
    if let Some(token) = auth_token {
        return validate_identity_token(&token, identity_store).await;
    }
    
    // No token - will need to be validated in handler with passphrase
    Err(Status::unauthenticated("Auth token required in metadata"))
}

/// Create gRPC interceptor function
/// 
/// This wraps the service to add authentication
pub fn create_auth_interceptor(
    identity_store: Arc<IdentityStore>,
    security_manager: Arc<SecurityManager>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |mut request: Request<()>| {
        // Extract auth_token from metadata
        let auth_token = extract_auth_token(&request);
        
        // For synchronous interceptor, we can't do async validation
        // Store token in extensions for async handler validation
        if let Some(token) = auth_token {
            request.extensions_mut().insert(token);
        }
        
        Ok(request)
    }
}
