//! Identity types and structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors related to identity operations
#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Identity not found: {0}")]
    IdentityNotFound(String),

    #[error("Invalid or revoked identity")]
    InvalidIdentity,

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Token mismatch")]
    TokenMismatch,
}

/// Result type for identity operations
pub type Result<T> = std::result::Result<T, IdentityError>;

impl From<IdentityError> for crate::Error {
    fn from(err: IdentityError) -> Self {
        crate::Error::Internal(err.to_string())
    }
}

/// Identity roles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityRole {
    Admin,
    Client,
}

impl Default for IdentityRole {
    fn default() -> Self {
        IdentityRole::Client
    }
}

/// Client types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientType {
    AiAgent,
    Service,
    User,
    Pkcs11,
}

impl std::fmt::Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientType::AiAgent => write!(f, "ai-agent"),
            ClientType::Service => write!(f, "service"),
            ClientType::User => write!(f, "user"),
            ClientType::Pkcs11 => write!(f, "pkcs11"),
        }
    }
}

impl std::str::FromStr for ClientType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "ai-agent" => Ok(ClientType::AiAgent),
            "service" => Ok(ClientType::Service),
            "user" => Ok(ClientType::User),
            "pkcs11" => Ok(ClientType::Pkcs11),
            _ => Err(format!("Unknown client type: {}", s)),
        }
    }
}

/// Supported key types for identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKeyType {
    Ed25519,
    P256,
}

impl Default for IdentityKeyType {
    fn default() -> Self {
        IdentityKeyType::Ed25519
    }
}

impl std::fmt::Display for IdentityKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityKeyType::Ed25519 => write!(f, "ed25519"),
            IdentityKeyType::P256 => write!(f, "p256"),
        }
    }
}

impl std::str::FromStr for IdentityKeyType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(IdentityKeyType::Ed25519),
            "p256" => Ok(IdentityKeyType::P256),
            _ => Err(format!("Unknown key type: {}", s)),
        }
    }
}

/// Identity structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Public key (base64 encoded, with prefix like "ed25519:...")
    pub public_key: String,

    /// Key type
    pub key_type: IdentityKeyType,

    /// SHA256 hash of token secret
    pub token_hash: String,

    /// Role
    pub role: IdentityRole,

    /// Client type
    pub client_type: ClientType,

    /// Optional description
    pub description: Option<String>,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last used timestamp
    pub last_used: DateTime<Utc>,

    /// Is identity active
    pub is_active: bool,
}

impl Identity {
    /// Create a new identity
    pub fn new(
        public_key: String,
        key_type: IdentityKeyType,
        token_hash: String,
        role: IdentityRole,
        client_type: ClientType,
        description: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            public_key,
            key_type,
            token_hash,
            role,
            client_type,
            description,
            created_at: now,
            last_used: now,
            is_active: true,
        }
    }

    /// Check if identity is admin
    pub fn is_admin(&self) -> bool {
        matches!(self.role, IdentityRole::Admin)
    }

    /// Update last used timestamp
    pub fn touch(&mut self) {
        self.last_used = Utc::now();
    }

    /// Revoke the identity
    pub fn revoke(&mut self) {
        self.is_active = false;
    }

    /// Get key namespace for this identity
    pub fn key_namespace(&self) -> String {
        format!("{}/keys/", self.public_key)
    }
}

/// Token structure (not stored, generated on creation)
#[derive(Debug)]
pub struct Token {
    /// Raw token string (base64 encoded)
    pub token: String,

    /// Public key
    pub public_key: String,

    /// Secret (random 32 bytes, base64 encoded)
    pub secret: String,

    /// Key type
    pub key_type: IdentityKeyType,
}

impl Token {
    /// Generate a new token for an identity
    pub fn generate(public_key: String, key_type: IdentityKeyType) -> (Self, String) {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use rand::Rng;

        // Generate random 32-byte secret
        let mut rng = rand::thread_rng();
        let secret_bytes: [u8; 32] = rng.gen();
        let secret = BASE64.encode(&secret_bytes);

        // Create token: base64(key_type:pubkey:secret)
        let raw_token = format!("{}:{}:{}", key_type, public_key, secret);
        let token = BASE64.encode(raw_token.as_bytes());

        // Hash the secret for storage
        let secret_hash = sha256_hex(&secret);

        (
            Self {
                token,
                public_key,
                secret,
                key_type,
            },
            secret_hash,
        )
    }

    /// Parse a token string
    pub fn parse(token_str: &str) -> Result<Self> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        // Decode base64
        let decoded = BASE64.decode(token_str).map_err(|e| {
            IdentityError::InvalidTokenFormat(format!("Base64 decode failed: {}", e))
        })?;

        let raw = String::from_utf8(decoded)
            .map_err(|e| IdentityError::InvalidTokenFormat(format!("Invalid UTF-8: {}", e)))?;

        // Parse: key_type:public_key:secret
        // Note: public_key itself may contain colons (e.g., "ed25519:abc123"), so split carefully
        // We need 4 parts: key_type, public_key_prefix, public_key_rest, secret
        // But public_key can have multiple colons, so we use splitn(4, ':') to get at most 4 parts
        let parts: Vec<&str> = raw.splitn(4, ':').collect();
        if parts.len() != 4 {
            return Err(IdentityError::InvalidTokenFormat(format!(
                "Expected 4 parts, got {}",
                parts.len()
            )));
        }

        let key_type: IdentityKeyType = parts[0]
            .parse()
            .map_err(|e| IdentityError::InvalidTokenFormat(e))?;
        // Reconstruct public_key from parts[1] and parts[2]
        let public_key = format!("{}:{}", parts[1], parts[2]);
        let secret = parts[3].to_string();

        Ok(Self {
            token: token_str.to_string(),
            public_key: public_key.to_string(),
            secret: secret.to_string(),
            key_type,
        })
    }

    /// Verify token against stored hash
    pub fn verify(&self, stored_hash: &str) -> bool {
        let computed_hash = sha256_hex(&self.secret);
        computed_hash == stored_hash
    }
}

/// SHA256 hash helper
fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generate_and_parse() {
        let pubkey = "ed25519:MCowBQYDK2VwAyEAabc123".to_string();
        let (token, hash) = Token::generate(pubkey.clone(), IdentityKeyType::Ed25519);

        // Verify token format
        assert!(!token.token.is_empty());
        assert_eq!(token.public_key, pubkey);
        assert!(!token.secret.is_empty());

        // Verify hash
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 hex = 64 chars

        // Verify token validation
        assert!(token.verify(&hash));
        assert!(!token.verify("wrong_hash"));

        // Parse token
        let parsed = Token::parse(&token.token).unwrap();
        assert_eq!(parsed.public_key, pubkey);
        assert_eq!(parsed.key_type, IdentityKeyType::Ed25519);
        assert_eq!(parsed.secret, token.secret);
    }

    #[test]
    fn test_identity_creation() {
        let identity = Identity::new(
            "ed25519:test123".to_string(),
            IdentityKeyType::Ed25519,
            "aabbccdd".to_string(),
            IdentityRole::Client,
            ClientType::AiAgent,
            Some("Test Bot".to_string()),
        );

        assert!(!identity.is_admin());
        assert_eq!(identity.client_type, ClientType::AiAgent);
        assert!(identity.is_active);
        assert_eq!(identity.key_namespace(), "ed25519:test123/keys/");
    }

    #[test]
    fn test_identity_role() {
        let client = Identity::new(
            "ed25519:client".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Client,
            ClientType::Service,
            None,
        );
        assert!(!client.is_admin());

        let admin = Identity::new(
            "ed25519:admin".to_string(),
            IdentityKeyType::Ed25519,
            "hash".to_string(),
            IdentityRole::Admin,
            ClientType::User,
            None,
        );
        assert!(admin.is_admin());
    }

    #[test]
    fn test_key_type_parsing() {
        assert_eq!(
            "ed25519".parse::<IdentityKeyType>().unwrap(),
            IdentityKeyType::Ed25519
        );
        assert_eq!(
            "p256".parse::<IdentityKeyType>().unwrap(),
            IdentityKeyType::P256
        );
        assert!("unknown".parse::<IdentityKeyType>().is_err());
    }

    #[test]
    fn test_client_type_parsing() {
        assert_eq!(
            "ai-agent".parse::<ClientType>().unwrap(),
            ClientType::AiAgent
        );
        assert_eq!(
            "service".parse::<ClientType>().unwrap(),
            ClientType::Service
        );
        assert_eq!("user".parse::<ClientType>().unwrap(), ClientType::User);
        assert_eq!("pkcs11".parse::<ClientType>().unwrap(), ClientType::Pkcs11);
        assert!("unknown".parse::<ClientType>().is_err());
    }
}
