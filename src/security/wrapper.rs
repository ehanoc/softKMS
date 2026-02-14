//! Key wrapping and unwrapping with AES-256-GCM
//!
//! This module provides the actual encryption/decryption of keys using AES-256-GCM
//! with per-key salts and authentication tags.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{MasterKey, Result, SecurityError};

/// Current version of the wrapped key format
pub const WRAPPED_KEY_VERSION: u8 = 1;

/// Wrapped (encrypted) key for storage
///
/// This structure contains all the information needed to decrypt a key:
/// - version: Algorithm version for future migrations
/// - salt: Unique salt for this key (used with master key)
/// - nonce: AES-GCM nonce (12 bytes)
/// - ciphertext: The encrypted key material
/// - tag: AES-GCM authentication tag (16 bytes)
/// - aad_hash: Hash of authenticated additional data
#[derive(Clone, Debug)]
pub struct WrappedKey {
    /// Format version
    pub version: u8,
    /// Per-key salt (32 bytes)
    pub salt: [u8; 32],
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Encrypted key material
    pub ciphertext: Vec<u8>,
    /// Authentication tag (16 bytes)
    pub tag: [u8; 16],
    /// Hash of AAD for integrity verification
    pub aad_hash: [u8; 32],
}

impl WrappedKey {
    /// Serialize to binary format
    ///
    /// Format: [version: 1][salt: 32][nonce: 12][tag: 16][aad_hash: 32][ciphertext: N]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 32 + 12 + 16 + 32 + self.ciphertext.len());

        result.push(self.version);
        result.extend_from_slice(&self.salt);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.tag);
        result.extend_from_slice(&self.aad_hash);
        result.extend_from_slice(&self.ciphertext);

        result
    }

    /// Deserialize from binary format
    ///
    /// # Errors
    ///
    /// Returns error if format is invalid or version is unsupported
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 93 {
            // 1 + 32 + 12 + 16 + 32 = 93 minimum
            return Err(SecurityError::InvalidWrappedKey);
        }

        let version = bytes[0];

        if version != WRAPPED_KEY_VERSION {
            return Err(SecurityError::VersionMismatch {
                expected: WRAPPED_KEY_VERSION,
                actual: version,
            });
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[1..33]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[33..45]);

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&bytes[45..61]);

        let mut aad_hash = [0u8; 32];
        aad_hash.copy_from_slice(&bytes[61..93]);

        let ciphertext = bytes[93..].to_vec();

        Ok(Self {
            version,
            salt,
            nonce,
            tag,
            aad_hash,
            ciphertext,
        })
    }

    /// Get total size in bytes
    pub fn size(&self) -> usize {
        1 + 32 + 12 + 16 + 32 + self.ciphertext.len()
    }
}

/// Key Encryption Key (KEK) derived from master key and per-key salt
/// Automatically zeroized when dropped for security
#[derive(Zeroize, ZeroizeOnDrop)]
struct KeyEncryptionKey {
    key: [u8; 32],
}

impl KeyEncryptionKey {
    /// Derive KEK from master key and salt using HKDF-SHA256
    fn derive(master_key: &MasterKey, salt: &[u8; 32]) -> Self {
        let master_key_bytes = master_key.expose_secret();
        let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key_bytes);
        let mut key = [0u8; 32];
        hkdf.expand(b"softkms-key-wrap-v1", &mut key)
            .expect("HKDF expansion failed - this should never happen with valid parameters");
        Self { key }
    }

    /// Get reference to the key bytes
    fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Key wrapper for encryption/decryption operations
pub struct KeyWrapper {
    master_key: MasterKey,
}

impl KeyWrapper {
    /// Create new key wrapper from master key
    pub fn new(master_key: MasterKey) -> Self {
        Self { master_key }
    }

    /// Wrap (encrypt) a key
    ///
    /// Encrypts the plaintext key material using AES-256-GCM.
    /// Each wrapped key gets a unique salt and nonce.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The raw key material to encrypt
    /// * `aad` - Additional authenticated data (e.g., key metadata)
    ///
    /// # Returns
    ///
    /// A `WrappedKey` containing the encrypted data
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use softkms::security::{MasterKey, KeyWrapper};
    ///
    /// let master_key = MasterKey::derive("passphrase", 210_000).unwrap();
    /// let wrapper = KeyWrapper::new(master_key);
    /// let wrapped = wrapper.wrap(&[1, 2, 3], b"metadata").unwrap();
    /// ```
    pub fn wrap(&self, plaintext: &[u8], aad: &[u8]) -> Result<WrappedKey> {
        // Generate per-key values
        let salt = Self::generate_salt();
        let nonce = Self::generate_nonce();

        // Derive per-key encryption key (KEK) from master key and salt
        // This provides defense-in-depth: even if AES has issues, the KEK is unique per key
        let kek = KeyEncryptionKey::derive(&self.master_key, &salt);

        // Create cipher from derived KEK
        let cipher = Aes256Gcm::new_from_slice(kek.as_bytes()).map_err(|e| {
            SecurityError::EncryptionFailed(format!("Failed to create cipher: {:?}", e))
        })?;

        // Build AAD with version info for future-proofing
        let aad_with_version =
            format!("softkms:v{}:wrap|{}", WRAPPED_KEY_VERSION, hex::encode(aad));

        // Encrypt
        let payload = Payload {
            msg: plaintext,
            aad: aad_with_version.as_bytes(),
        };

        let nonce_obj = Nonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_obj, payload)
            .map_err(|e| SecurityError::EncryptionFailed(e.to_string()))?;

        // Split ciphertext and tag
        // AES-GCM returns ciphertext || tag (16 bytes)
        let ct_len = ciphertext.len().saturating_sub(16);
        let (ct, tag_bytes) = ciphertext.split_at(ct_len);

        let mut tag = [0u8; 16];
        if tag_bytes.len() == 16 {
            tag.copy_from_slice(tag_bytes);
        } else {
            return Err(SecurityError::EncryptionFailed(
                "Invalid tag length".to_string(),
            ));
        }

        // Hash AAD for integrity verification
        let mut hasher = Sha256::new();
        hasher.update(aad_with_version.as_bytes());
        let aad_hash = hasher.finalize().into();

        Ok(WrappedKey {
            version: WRAPPED_KEY_VERSION,
            salt,
            nonce,
            tag,
            aad_hash,
            ciphertext: ct.to_vec(),
        })
    }

    /// Unwrap (decrypt) a key
    ///
    /// Decrypts the wrapped key material and returns the plaintext.
    /// Verifies AAD integrity before decryption.
    ///
    /// # Arguments
    ///
    /// * `wrapped` - The wrapped key to decrypt
    /// * `aad` - Additional authenticated data (must match what was used during wrap)
    ///
    /// # Returns
    ///
    /// The decrypted key material
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Version mismatch
    /// - AAD integrity check fails
    /// - Decryption fails (wrong passphrase or tampered data)
    pub fn unwrap(&self, wrapped: &WrappedKey, aad: &[u8]) -> Result<Vec<u8>> {
        // Check version
        if wrapped.version != WRAPPED_KEY_VERSION {
            return Err(SecurityError::VersionMismatch {
                expected: WRAPPED_KEY_VERSION,
                actual: wrapped.version,
            });
        }

        // Verify AAD integrity
        let aad_with_version =
            format!("softkms:v{}:wrap|{}", WRAPPED_KEY_VERSION, hex::encode(aad));

        let mut hasher = Sha256::new();
        hasher.update(aad_with_version.as_bytes());
        let expected_hash: [u8; 32] = hasher.finalize().into();

        if wrapped.aad_hash != expected_hash {
            return Err(SecurityError::AadIntegrityFailed);
        }

        // Derive the same KEK used during wrap using the stored salt
        let kek = KeyEncryptionKey::derive(&self.master_key, &wrapped.salt);

        // Create cipher from derived KEK
        let cipher = Aes256Gcm::new_from_slice(kek.as_bytes()).map_err(|e| {
            SecurityError::DecryptionFailed(format!("Failed to create cipher: {:?}", e))
        })?;

        // Reconstruct ciphertext with tag
        let mut full_ciphertext = wrapped.ciphertext.clone();
        full_ciphertext.extend_from_slice(&wrapped.tag);

        // Decrypt
        let payload = Payload {
            msg: &full_ciphertext,
            aad: aad_with_version.as_bytes(),
        };

        let nonce_obj = Nonce::from_slice(&wrapped.nonce);
        let plaintext = cipher
            .decrypt(nonce_obj, payload)
            .map_err(|e| SecurityError::DecryptionFailed(e.to_string()))?;

        // Clear sensitive data from memory
        drop(full_ciphertext);

        Ok(plaintext)
    }

    /// Generate random salt
    fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// Generate random nonce
    fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let master_key = MasterKey::derive("test", 1000).unwrap();
        let wrapper = KeyWrapper::new(master_key);

        let plaintext = b"secret key material";
        let aad = b"key metadata";

        let wrapped = wrapper.wrap(plaintext, aad).unwrap();
        let decrypted = wrapper.unwrap(&wrapped, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_aad() {
        let master_key = MasterKey::derive("test", 1000).unwrap();
        let wrapper = KeyWrapper::new(master_key);

        let plaintext = b"secret key material";
        let wrapped = wrapper.wrap(plaintext, b"correct aad").unwrap();

        // Try to unwrap with wrong AAD
        let result = wrapper.unwrap(&wrapped, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_passphrase() {
        let key1 = MasterKey::derive("passphrase1", 1000).unwrap();
        let wrapper1 = KeyWrapper::new(key1);

        let plaintext = b"secret key material";
        let aad = b"metadata";
        let wrapped = wrapper1.wrap(plaintext, aad).unwrap();

        // Try to unwrap with different passphrase
        let key2 = MasterKey::derive("passphrase2", 1000).unwrap();
        let wrapper2 = KeyWrapper::new(key2);

        let result = wrapper2.unwrap(&wrapped, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization() {
        let master_key = MasterKey::derive("test", 1000).unwrap();
        let wrapper = KeyWrapper::new(master_key);

        let wrapped = wrapper.wrap(b"test", b"aad").unwrap();
        let bytes = wrapped.to_bytes();
        let restored = WrappedKey::from_bytes(&bytes).unwrap();

        assert_eq!(wrapped.version, restored.version);
        assert_eq!(wrapped.salt, restored.salt);
        assert_eq!(wrapped.nonce, restored.nonce);
        assert_eq!(wrapped.tag, restored.tag);
        assert_eq!(wrapped.aad_hash, restored.aad_hash);
        assert_eq!(wrapped.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_invalid_bytes_too_short() {
        let result = WrappedKey::from_bytes(&[1u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_mismatch() {
        let master_key = MasterKey::derive("test", 1000).unwrap();
        let wrapper = KeyWrapper::new(master_key);

        let mut wrapped = wrapper.wrap(b"test", b"aad").unwrap();
        wrapped.version = 99; // Change version

        let bytes = wrapped.to_bytes();
        let result = WrappedKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_unique_salts() {
        let master_key = MasterKey::derive("test", 1000).unwrap();
        let wrapper = KeyWrapper::new(master_key);

        let wrapped1 = wrapper.wrap(b"test1", b"aad1").unwrap();
        let wrapped2 = wrapper.wrap(b"test2", b"aad2").unwrap();

        // Each wrapped key should have unique salt
        assert_ne!(wrapped1.salt, wrapped2.salt);
    }

    #[test]
    fn test_unique_nonces() {
        let master_key = MasterKey::derive("test", 1000).unwrap();
        let wrapper = KeyWrapper::new(master_key);

        let wrapped1 = wrapper.wrap(b"test1", b"aad1").unwrap();
        let wrapped2 = wrapper.wrap(b"test2", b"aad2").unwrap();

        // Each wrapped key should have unique nonce
        assert_ne!(wrapped1.nonce, wrapped2.nonce);
    }
}
