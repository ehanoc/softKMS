//! WebAuthn/FIDO2 Types and Constants
//!
//! This module defines the core types used in WebAuthn/FIDO2 operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// WebAuthn credential data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Unique credential identifier
    pub credential_id: Vec<u8>,
    /// Relying Party ID (e.g., "github.com")
    pub rp_id: String,
    /// Opaque user handle
    pub user_handle: Vec<u8>,
    /// Human-readable username
    pub user_name: Option<String>,
    /// Human-readable display name
    pub display_name: Option<String>,
    /// Public key in COSE format
    pub public_key: Vec<u8>,
    /// Private key reference (encrypted)
    pub private_key_id: Uuid,
    /// Signature counter for replay protection
    pub sign_count: u32,
    /// Whether this is a resident/discoverable credential
    pub is_resident: bool,
    /// Credential creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
    /// HD wallet derivation path (if derived from seed)
    pub derivation_path: Option<String>,
}

/// Credential key pair (private + public)
#[derive(Debug, Clone)]
pub struct CredentialKeyPair {
    /// Credential ID this key belongs to
    pub credential_id: Vec<u8>,
    /// Private key material (encrypted reference)
    pub private_key_id: Uuid,
    /// Public key in COSE format
    pub public_key: Vec<u8>,
    /// Algorithm (ES256, Ed25519, etc.)
    pub algorithm: CredentialAlgorithm,
}

/// Supported credential algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialAlgorithm {
    /// ECDSA with P-256 and SHA-256 (required by WebAuthn)
    Es256,
    /// EdDSA with Ed25519 (optional)
    Ed25519,
    /// ECDSA with P-384 and SHA-384
    Es384,
    /// ECDSA with P-521 and SHA-512
    Es512,
}

impl CredentialAlgorithm {
    /// Get the COSE algorithm identifier
    pub fn to_cose_id(self) -> i32 {
        match self {
            CredentialAlgorithm::Es256 => -7,   // ECDSA w/ SHA-256
            CredentialAlgorithm::Ed25519 => -8, // EdDSA
            CredentialAlgorithm::Es384 => -35,  // ECDSA w/ SHA-384
            CredentialAlgorithm::Es512 => -36,  // ECDSA w/ SHA-512
        }
    }

    /// Get the algorithm name
    pub fn name(self) -> &'static str {
        match self {
            CredentialAlgorithm::Es256 => "ES256",
            CredentialAlgorithm::Ed25519 => "EdDSA",
            CredentialAlgorithm::Es384 => "ES384",
            CredentialAlgorithm::Es512 => "ES512",
        }
    }
}

/// User verification requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserVerification {
    /// User verification required
    Required,
    /// User verification preferred (will be performed if available)
    Preferred,
    /// User verification discouraged
    Discouraged,
}

/// Authenticator attachment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatorAttachment {
    /// Platform authenticator (built-in, e.g., TouchID)
    Platform,
    /// Roaming authenticator (external, e.g., USB security key)
    CrossPlatform,
}

/// Resident key requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResidentKey {
    /// Resident key required (discoverable credential)
    Required,
    /// Resident key preferred
    Preferred,
    /// Resident key discouraged
    Discouraged,
}

/// Credential filter for searching
#[derive(Debug, Clone, Default)]
pub struct CredentialFilter {
    /// Filter by relying party ID
    pub rp_id: Option<String>,
    /// Filter by user handle
    pub user_handle: Option<Vec<u8>>,
    /// Filter by credential ID
    pub credential_id: Option<Vec<u8>>,
    /// Only include resident credentials
    pub resident_only: bool,
}

/// CTAP2 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2Error {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    UnsupportedExtension = 0x16,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UserPresenceRequired = 0x2F,
    UserVerificationRequired = 0x30,
    UserVerificationBlocked = 0x32,
    UserVerificationInvalid = 0x34,
    UserVerificationCancelled = 0x36,
    UserVerificationTimeout = 0x37,
    Other = 0x7F,
}

/// WebAuthn credential creation options
#[derive(Debug, Clone)]
pub struct CredentialCreationOptions {
    /// Relying party information
    pub rp: RelyingParty,
    /// User information
    pub user: UserInfo,
    /// Challenge from the server
    pub challenge: Vec<u8>,
    /// Allowed credential parameters
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout in milliseconds
    pub timeout: Option<u32>,
    /// User verification requirement
    pub user_verification: UserVerification,
    /// Resident key requirement
    pub resident_key: ResidentKey,
    /// Seed for deterministic credential generation (optional)
    pub derivation_seed: Option<Vec<u8>>,
}

/// Relying party information
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// Relying party ID (domain)
    pub id: String,
    /// Human-readable name
    pub name: Option<String>,
}

/// User information
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Opaque user handle
    pub id: Vec<u8>,
    /// Username
    pub name: String,
    /// Display name
    pub display_name: Option<String>,
}

/// Public key credential parameters
#[derive(Debug, Clone)]
pub struct PublicKeyCredentialParameters {
    /// Credential type
    pub cred_type: String,
    /// COSE algorithm identifier
    pub alg: i32,
}

/// WebAuthn assertion/get options
#[derive(Debug, Clone)]
pub struct AssertionOptions {
    /// Challenge from the server
    pub challenge: Vec<u8>,
    /// Timeout in milliseconds
    pub timeout: Option<u32>,
    /// Relying party ID
    pub rp_id: String,
    /// List of allowed credentials
    pub allow_credentials: Vec<AllowedCredential>,
    /// User verification requirement
    pub user_verification: UserVerification,
}

/// Allowed credential for assertion
#[derive(Debug, Clone)]
pub struct AllowedCredential {
    /// Credential type
    pub cred_type: String,
    /// Credential ID
    pub id: Vec<u8>,
}

/// Authenticator assertion response
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionResponse {
    /// Credential ID used
    pub credential_id: Vec<u8>,
    /// Authenticator data
    pub authenticator_data: Vec<u8>,
    /// Client data hash
    pub client_data_hash: Vec<u8>,
    /// Signature
    pub signature: Vec<u8>,
    /// User handle (for resident credentials)
    pub user_handle: Option<Vec<u8>>,
    /// Number of credentials in authenticator (for resident credentials)
    pub number_of_credentials: Option<usize>,
}

/// Attestation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationType {
    /// No attestation
    None,
    /// Self attestation
    Self_,
    /// Basic attestation (with attestation certificate)
    Basic,
    /// Attestation CA
    AttCa,
}

/// CTAP2 command codes
pub const CTAP2_COMMAND_MAKE_CREDENTIAL: u8 = 0x01;
pub const CTAP2_COMMAND_GET_ASSERTION: u8 = 0x02;
pub const CTAP2_COMMAND_GET_INFO: u8 = 0x04;
pub const CTAP2_COMMAND_CLIENT_PIN: u8 = 0x06;
pub const CTAP2_COMMAND_RESET: u8 = 0x07;
pub const CTAP2_COMMAND_GET_NEXT_ASSERTION: u8 = 0x08;
pub const CTAP2_COMMAND_CRED_MGMT: u8 = 0x0A;

/// BIP32 purpose for WebAuthn credentials
pub const WEBAUTHN_BIP32_PURPOSE: u32 = 2017;

/// Derivation path prefix for WebAuthn
pub const WEBAUTHN_DERIVATION_PREFIX: &str = "m/2017'";
