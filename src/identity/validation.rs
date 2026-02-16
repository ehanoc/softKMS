//! Token validation and auth extraction

use tonic::{Request, Status};

use crate::identity::types::{Identity, IdentityError, Token, IdentityRole};
use crate::identity::storage::IdentityStore;

/// Extract token from gRPC request
/// 
/// Priority:
/// 1. Authorization header with "Bearer " prefix
/// 2. Request extension (from previous interceptor)
/// 3. Request metadata
pub fn extract_token_from_request(req: &Request<()>) -> Result<String, Status> {
    // Check metadata for authorization header
    if let Some(token) = extract_from_metadata(req, "authorization") {
        // Strip "Bearer " prefix if present
        let token = token.strip_prefix("Bearer ").unwrap_or(&token);
        return Ok(token.to_string());
    }
    
    // Check for x-softkms-token header
    if let Some(token) = extract_from_metadata(req, "x-softkms-token") {
        return Ok(token);
    }
    
    // Try to get from extensions (if another interceptor set it)
    if let Some(token) = req.extensions().get::<String>() {
        return Ok(token.clone());
    }
    
    Err(Status::unauthenticated("No authentication token provided"))
}

fn extract_from_metadata(req: &Request<()>, key: &str) -> Option<String> {
    req.metadata()
        .get(key)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Validate a token and return the corresponding identity
pub async fn validate_token(
    store: &IdentityStore,
    token_str: &str,
) -> crate::identity::types::Result<Identity> {
    // Parse token
    let token = Token::parse(token_str)?;
    
    // Load identity
    let mut identity = store.load(&token.public_key).await?;
    
    // Check if active
    if !identity.is_active {
        return Err(IdentityError::InvalidIdentity);
    }
    
    // Verify token hash
    if !token.verify(&identity.token_hash) {
        return Err(IdentityError::TokenMismatch);
    }
    
    // Update last used
    identity.touch();
    store.update(&identity).await?;
    
    Ok(identity)
}

/// Check if identity can access a resource
pub fn can_access(identity: &Identity, resource: &str) -> bool {
    match identity.role {
        IdentityRole::Admin => {
            // Admin can access all resources
            true
        }
        IdentityRole::Client => {
            // Client can only access resources in their namespace
            let prefix = identity.key_namespace();
            resource.starts_with(&prefix)
        }
    }
}

/// Get resource path from key ID
pub fn get_resource_path(key_id: &str, identity: &Identity) -> String {
    format!("{}{}", identity.key_namespace(), key_id)
}

/// Check if identity can perform action on resource
pub fn check_permission(
    identity: &Identity,
    action: &str,
    resource: &str,
) -> crate::identity::types::Result<()> {
    if !can_access(identity, resource) {
        return Err(IdentityError::AccessDenied(format!(
            "Identity {} cannot {} {}",
            identity.public_key, action, resource
        )));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::types::{ClientType, IdentityKeyType};
    
    #[test]
    fn test_can_access_admin() {
        let admin = Identity::new(
            "ed25519:admin".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Admin,
            ClientType::User,
            None,
        );
        
        assert!(can_access(&admin, "any/resource/path"));
        assert!(can_access(&admin, "ed25519:client1/keys/key1"));
    }
    
    #[test]
    fn test_can_access_client() {
        let client = Identity::new(
            "ed25519:client1".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Client,
            ClientType::AiAgent,
            None,
        );
        
        // Can access own namespace
        assert!(can_access(&client, "ed25519:client1/keys/key1"));
        assert!(can_access(&client, "ed25519:client1/keys/key2"));
        
        // Cannot access other namespaces
        assert!(!can_access(&client, "ed25519:client2/keys/key1"));
        assert!(!can_access(&client, "admin/key1"));
        assert!(!can_access(&client, "some/other/path"));
    }
    
    #[test]
    fn test_check_permission() {
        let client = Identity::new(
            "ed25519:client1".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Client,
            ClientType::AiAgent,
            None,
        );
        
        // Should succeed
        assert!(check_permission(&client, "Sign", "ed25519:client1/keys/key1"
        ).is_ok());
        
        // Should fail
        assert!(check_permission(
            &client,
            "Sign",
            "ed25519:client2/keys/key1"
        ).is_err());
    }
    
    #[test]
    fn test_get_resource_path() {
        let client = Identity::new(
            "ed25519:client1".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Client,
            ClientType::AiAgent,
            None,
        );
        
        let path = get_resource_path("key_001", &client);
        assert_eq!(path, "ed25519:client1/keys/key_001");
    }
}
