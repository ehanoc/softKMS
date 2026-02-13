//! Cryptographic engine implementations

pub mod ed25519;
pub mod p256;

use secrecy::Secret;

/// Trait for cryptographic engines
trait CryptoEngine {
    /// Generate a new key
    fn generate_key(&self, params: KeyParams) -> crate::Result<Key>;

    /// Sign data
    fn sign(&self, key: &Key, data: &[u8]) -> crate::Result<Signature>;

    /// Verify signature
    fn verify(&self, key: &Key, data: &[u8], sig: &Signature) -> crate::Result<bool>;
}

/// Key parameters
#[derive(Debug, Clone)]
pub struct KeyParams {
    /// Algorithm (ed25519, ecdsa, rsa, etc.)
    pub algorithm: String,
    /// Curve for ECDSA (secp256k1, secp256r1, etc.)
    pub curve: Option<String>,
    /// Key size for RSA
    pub key_size: Option<u32>,
}

/// Private key (securely stored)
pub struct Key {
    /// Key ID
    pub id: crate::KeyId,
    /// Key material (encrypted)
    pub material: Secret<Vec<u8>>,
    /// Public key
    pub public_key: Vec<u8>,
    /// Metadata
    pub metadata: crate::KeyMetadata,
}

/// Signature
#[derive(Debug, Clone)]
pub struct Signature {
    /// Signature bytes
    pub bytes: Vec<u8>,
    /// Algorithm used
    pub algorithm: String,
}
