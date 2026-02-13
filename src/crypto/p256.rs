//! Deterministic P-256 (secp256r1) key derivation and signing
//!
//! This module implements deterministic P-256 key derivation from BIP39 seeds,
//! following the same methodology as the Algorand Foundation's deterministic-P256-ts
//! library but adapted for the softKMS architecture.
//!
//! Algorithm:
//! 1. Seed (from BIP39) is already stored encrypted in softKMS
//! 2. To derive a P-256 key: SHA-512(seed_material + origin + user_handle + counter)
//! 3. First 32 bytes of hash = private key seed
//! 4. Validate seed is in valid range [1, n-1] for P-256 curve
//! 5. Use p256 crate for ECDSA operations

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use std::convert::TryInto;

use crate::{Error, Result};

/// P-256 curve order (n)
/// From NIST SP 800-186
const P256_CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Deterministic P-256 key derivation context
pub struct DeterministicP256;

impl DeterministicP256 {
    /// Generate a deterministic P-256 private key from seed material and context
    ///
    /// # Arguments
    /// * `seed_material` - The 64-byte derived main key from BIP39 seed
    /// * `origin` - Domain/origin (e.g., "github.com")
    /// * `user_handle` - User identifier (e.g., "user@example.com")
    /// * `counter` - Optional counter for multiple keys per service (default: 0)
    ///
    /// # Returns
    /// 32-byte private key seed that's valid for P-256 curve
    pub fn derive_key(
        seed_material: &[u8],
        origin: &str,
        user_handle: &str,
        counter: u32,
    ) -> Result<Vec<u8>> {
        // Encode origin and user_handle as UTF-8
        let origin_bytes = origin.as_bytes();
        let user_handle_bytes = user_handle.as_bytes();

        // Convert counter to big-endian 4 bytes
        let counter_bytes = counter.to_be_bytes();

        // Concatenate: seed + origin + user_handle + counter
        let total_len = seed_material.len() + origin_bytes.len() + user_handle_bytes.len() + 4;
        let mut input = Vec::with_capacity(total_len);
        input.extend_from_slice(seed_material);
        input.extend_from_slice(origin_bytes);
        input.extend_from_slice(user_handle_bytes);
        input.extend_from_slice(&counter_bytes);

        // SHA-512 hash
        let hash = Sha512::digest(&input);

        // Use first 32 bytes as seed
        let mut seed: Vec<u8> = hash[..32].to_vec();

        // Ensure valid private key (in range [1, n-1])
        if !Self::is_valid_private_key(&seed) {
            // Re-hash with SHA-256 if first attempt produces invalid key
            use sha2::Sha256;
            seed = Sha256::digest(&seed).to_vec();

            if !Self::is_valid_private_key(&seed) {
                return Err(Error::Crypto(
                    "Failed to generate valid P-256 private key".to_string(),
                ));
            }
        }

        Ok(seed)
    }

    /// Validate that a 32-byte array is a valid P-256 private key
    /// Must be in range [1, n-1] where n is the curve order
    fn is_valid_private_key(key: &[u8]) -> bool {
        if key.len() != 32 {
            return false;
        }

        // Check key > 0
        let is_zero = key.iter().all(|&b| b == 0);
        if is_zero {
            return false;
        }

        // Check key < curve_order (n)
        // Compare byte by byte from most significant
        for i in 0..32 {
            if key[i] < P256_CURVE_ORDER[i] {
                return true;
            } else if key[i] > P256_CURVE_ORDER[i] {
                return false;
            }
        }

        // Equal to curve order - not valid (must be strictly less)
        false
    }

    /// Create a P-256 signing key from seed
    pub fn create_signing_key(seed: &[u8]) -> Result<SigningKey> {
        let seed_array: [u8; 32] = seed
            .try_into()
            .map_err(|_| Error::Crypto("Invalid seed length for P-256 key".to_string()))?;

        let signing_key = SigningKey::from_bytes(&seed_array.into())
            .map_err(|e| Error::Crypto(format!("Invalid P-256 signing key: {}", e)))?;

        Ok(signing_key)
    }

    /// Sign data using P-256 private key
    /// Returns raw 64-byte signature (r || s)
    pub fn sign(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = Self::create_signing_key(private_key)?;
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify P-256 signature
    pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| Error::Crypto(format!("Invalid P-256 public key: {}", e)))?;

        let sig = Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("Invalid P-256 signature: {}", e)))?;

        match verifying_key.verify(data, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get public key from private key
    pub fn get_public_key(private_key: &[u8]) -> Result<Vec<u8>> {
        let signing_key = Self::create_signing_key(private_key)?;
        let verifying_key = VerifyingKey::from(&signing_key);
        // Return uncompressed format (0x04 || X || Y) = 65 bytes
        // Or compressed format (0x02 or 0x03 || X) = 33 bytes
        // WebAuthn typically uses uncompressed
        Ok(verifying_key.to_encoded_point(false).as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_seed() -> Vec<u8> {
        // A 64-byte test seed (simulating PBKDF2 output from BIP39)
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ]
    }

    #[test]
    fn test_derive_key_determinism() {
        let seed = create_test_seed();
        let origin = "github.com";
        let user_handle = "user@example.com";
        let counter = 0u32;

        // Derive twice with same inputs
        let key1 = DeterministicP256::derive_key(&seed, origin, user_handle, counter).unwrap();
        let key2 = DeterministicP256::derive_key(&seed, origin, user_handle, counter).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_derive_key_different_inputs() {
        let seed = create_test_seed();

        let key1 = DeterministicP256::derive_key(&seed, "github.com", "user1", 0).unwrap();
        let key2 = DeterministicP256::derive_key(&seed, "github.com", "user2", 0).unwrap();
        let key3 = DeterministicP256::derive_key(&seed, "gitlab.com", "user1", 0).unwrap();

        // Different inputs should produce different keys
        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = create_test_seed();
        let private_key = DeterministicP256::derive_key(&seed, "test.com", "user", 0).unwrap();

        let data = b"Hello, World!";
        let signature = DeterministicP256::sign(&private_key, data).unwrap();

        // Signature should be 64 bytes (r || s)
        assert_eq!(signature.len(), 64);

        // Get public key
        let public_key = DeterministicP256::get_public_key(&private_key).unwrap();

        // Verify
        let valid = DeterministicP256::verify(&public_key, data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_data() {
        let seed = create_test_seed();
        let private_key = DeterministicP256::derive_key(&seed, "test.com", "user", 0).unwrap();

        let data = b"Hello, World!";
        let signature = DeterministicP256::sign(&private_key, data).unwrap();
        let public_key = DeterministicP256::get_public_key(&private_key).unwrap();

        // Verify with wrong data
        let valid = DeterministicP256::verify(&public_key, b"Wrong data", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_valid_private_key_check() {
        // Zero key is invalid
        let zero_key = vec![0u8; 32];
        assert!(!DeterministicP256::is_valid_private_key(&zero_key));

        // Key equal to curve order is invalid
        assert!(!DeterministicP256::is_valid_private_key(&P256_CURVE_ORDER));

        // Valid key (1)
        let one_key = {
            let mut k = vec![0u8; 32];
            k[31] = 1;
            k
        };
        assert!(DeterministicP256::is_valid_private_key(&one_key));
    }
}
