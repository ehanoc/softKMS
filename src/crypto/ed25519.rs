//! Ed25519 cryptographic engine implementation
//!
//! This module provides Ed25519 signing using the ed25519-dalek crate.
//! Keys are generated, used, and then immediately cleared from memory.

use ed25519_dalek::{Signature as DalekSignature, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;

use crate::{Error, KeyId, KeyMetadata, Result, Signature};

/// Ed25519 key size constants
pub const ED25519_SECRET_KEY_SIZE: usize = SECRET_KEY_LENGTH; // 32 bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH; // 32 bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64; // 64 bytes

/// Ed25519 cryptographic engine
pub struct Ed25519Engine;

impl Ed25519Engine {
    /// Generate a new Ed25519 key pair
    ///
    /// # Arguments
    /// * `metadata` - Key metadata
    ///
    /// # Returns
    /// * Tuple of (secret_key, public_key, metadata)
    pub fn generate_key(
        metadata: KeyMetadata,
    ) -> Result<(Secret<[u8; 32]>, [u8; 32], KeyMetadata)> {
        // Generate signing key using OS RNG
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Extract key material
        let secret_bytes: [u8; SECRET_KEY_LENGTH] = signing_key.to_bytes();
        let public_bytes: [u8; PUBLIC_KEY_LENGTH] = verifying_key.to_bytes();

        // Clear the signing_key (ZeroizeOnDrop should handle this)
        drop(signing_key);

        Ok((Secret::new(secret_bytes), public_bytes, metadata))
    }

    /// Sign data with a secret key
    ///
    /// # Arguments
    /// * `secret_key` - The Ed25519 secret key (32 bytes)
    /// * `data` - Data to sign
    ///
    /// # Returns
    /// * `Signature` - The computed signature
    ///
    /// # Security
    /// The secret key is temporarily exposed during signing.
    pub fn sign(secret_key: &Secret<[u8; 32]>, data: &[u8]) -> Result<Signature> {
        // Reconstruct signing key from secret
        let secret_bytes = secret_key.expose_secret();
        let signing_key = SigningKey::from_bytes(secret_bytes);

        // Sign the data
        let signature = signing_key.sign(data);

        // Clear the reconstructed signing key
        drop(signing_key);

        Ok(Signature {
            bytes: signature.to_bytes().to_vec(),
            algorithm: "ed25519".to_string(),
        })
    }

    /// Verify a signature
    ///
    /// # Arguments
    /// * `public_key` - The public key (32 bytes)
    /// * `data` - Data that was signed
    /// * `signature` - The signature to verify (64 bytes)
    ///
    /// # Returns
    /// * `bool` - True if signature is valid
    pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        // Parse public key
        if public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(Error::Crypto(format!(
                "Invalid public key length: expected {}, got {}",
                PUBLIC_KEY_LENGTH,
                public_key.len()
            )));
        }

        let mut pk_bytes = [0u8; PUBLIC_KEY_LENGTH];
        pk_bytes.copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| Error::Crypto(format!("Invalid public key: {}", e)))?;

        // Parse signature
        if signature.len() != 64 {
            return Err(Error::Crypto(format!(
                "Invalid signature length: expected 64, got {}",
                signature.len()
            )));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = DalekSignature::from_bytes(&sig_bytes);

        // Verify
        match verifying_key.verify_strict(data, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn create_test_metadata() -> KeyMetadata {
        KeyMetadata {
            id: KeyId::new_v4(),
            label: Some("test-key".to_string()),
            algorithm: "ed25519".to_string(),
            key_type: crate::KeyType::Imported,
            created_at: Utc::now(),
            attributes: HashMap::new(),
            public_key: Vec::new(),
        }
    }

    #[test]
    fn test_key_generation() {
        let metadata = create_test_metadata();
        let (secret, public_key, _) = Ed25519Engine::generate_key(metadata).unwrap();

        assert_eq!(secret.expose_secret().len(), 32);
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let metadata = create_test_metadata();
        let (secret, public_key, _) = Ed25519Engine::generate_key(metadata).unwrap();

        let data = b"test message";
        let signature = Ed25519Engine::sign(&secret, data).unwrap();

        assert_eq!(signature.bytes.len(), 64);
        assert_eq!(signature.algorithm, "ed25519");

        let valid = Ed25519Engine::verify(&public_key, data, &signature.bytes).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_data() {
        let metadata = create_test_metadata();
        let (secret, public_key, _) = Ed25519Engine::generate_key(metadata).unwrap();

        let data = b"test message";
        let signature = Ed25519Engine::sign(&secret, data).unwrap();

        let valid = Ed25519Engine::verify(&public_key, b"wrong message", &signature.bytes).unwrap();
        assert!(!valid);
    }
}
