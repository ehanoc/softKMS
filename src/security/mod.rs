//! Security Layer - Master key derivation and key wrapping
//!
//! This module provides encryption at rest for softKMS. All sensitive key material
//! is encrypted with AES-256-GCM using a master key derived from the user's passphrase.
//!
//! # Security Model
//!
//! ```text
//! Passphrase + PBKDF2 (210k rounds) → Master Key (AES-256)
//!                                       ↓
//!                              AES-GCM + Per-key Salt
//!                                       ↓
//!                              Wrapped Key (binary format)
//! ```
//!
//! # Key Features
//!
//! - **Passphrase-derived**: Master key never stored, always derived
//! - **Per-key salts**: Each wrapped key has unique 32-byte salt
//! - **Memory protection**: Optional mlock to prevent swapping
//! - **Zeroization**: Automatic clearing of sensitive memory
//! - **Thread-safe**: Global Mutex for master key caching
//!
//! # Binary Format
//!
//! ```text
//! [version: 1 byte][salt: 32 bytes][nonce: 12 bytes][ciphertext: N][tag: 16 bytes]
//! ```

pub mod config;
pub mod error;
pub mod master_key;
pub mod wrapper;

use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use config::SecurityConfig;
pub use error::{Result, SecurityError};
pub use master_key::MasterKey;
pub use wrapper::{KeyWrapper, WrappedKey};

/// Global master key cache with TTL
///
/// Thread-safe storage for the derived master key to avoid
/// prompting for passphrase on every operation.
pub struct MasterKeyCache {
    key: Option<Arc<Secret<[u8; 32]>>>,
    derived_at: Option<Instant>,
    ttl: Duration,
}

impl MasterKeyCache {
    /// Create new cache with specified TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            key: None,
            derived_at: None,
            ttl,
        }
    }

    /// Check if cached key exists and is not expired
    pub fn is_valid(&self) -> bool {
        if let (Some(ref _key), Some(derived_at)) = (&self.key, self.derived_at) {
            derived_at.elapsed() < self.ttl
        } else {
            false
        }
    }

    /// Get cached key if valid
    pub fn get(&self) -> Option<Arc<Secret<[u8; 32]>>> {
        if self.is_valid() {
            self.key.clone()
        } else {
            None
        }
    }

    /// Store key in cache
    pub fn store(&mut self, key: Secret<[u8; 32]>) {
        self.key = Some(Arc::new(key));
        self.derived_at = Some(Instant::now());
    }

    /// Clear cached key
    pub fn clear(&mut self) {
        self.key = None;
        self.derived_at = None;
    }
}

/// Thread-safe global cache
pub type SharedCache = Arc<Mutex<MasterKeyCache>>;

/// Create a new shared cache
pub fn create_cache(ttl_seconds: u64) -> SharedCache {
    Arc::new(Mutex::new(MasterKeyCache::new(Duration::from_secs(
        ttl_seconds,
    ))))
}

/// Security manager - main interface for security operations
pub struct SecurityManager {
    cache: SharedCache,
    config: SecurityConfig,
    verification_hash_path: PathBuf,
    /// In-memory verification hash for runtime passphrase validation
    verification_hash: std::sync::Mutex<Option<[u8; 32]>>,
}

impl SecurityManager {
    /// Create new security manager
    pub fn new(cache: SharedCache, config: SecurityConfig, storage_path: PathBuf) -> Self {
        let verification_hash_path = storage_path.join(".verification_hash");
        Self {
            cache,
            config,
            verification_hash_path,
            verification_hash: std::sync::Mutex::new(None),
        }
    }

    /// Set the verification hash for passphrase validation
    ///
    /// This should be called during initialization with the correct master key hash.
    /// The hash is stored in memory to verify subsequent passphrase entries.
    pub fn set_verification_hash(&self, hash: [u8; 32]) {
        let mut guard = self.verification_hash.lock().unwrap();
        *guard = Some(hash);
    }

    /// Verify a passphrase against the stored verification hash
    ///
    /// Derives the master key from the passphrase and checks if it matches
    /// the stored verification hash. Returns true if the passphrase is correct.
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool> {
        // Check if we have a verification hash stored
        let expected_hash = {
            let guard = self
                .verification_hash
                .lock()
                .map_err(|_| SecurityError::LockPoisoned)?;
            match *guard {
                Some(hash) => hash,
                None => {
                    // No verification hash yet - check if one exists on disk
                    if self.verification_hash_path.exists() {
                        let stored_hash =
                            std::fs::read(&self.verification_hash_path).map_err(|e| {
                                SecurityError::Storage(format!(
                                    "Failed to read verification hash: {}",
                                    e
                                ))
                            })?;
                        if stored_hash.len() == 32 {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&stored_hash);
                            hash
                        } else {
                            return Err(SecurityError::Storage(
                                "Invalid verification hash file".to_string(),
                            ));
                        }
                    } else {
                        return Err(SecurityError::InvalidPassphrase(
                            "Keystore not initialized".to_string(),
                        ));
                    }
                }
            }
        };

        // Derive key from passphrase
        let master_key = MasterKey::derive(passphrase, self.config.pbkdf2_iterations)?;
        let derived_hash = Self::compute_verification_hash(&master_key);

        // Compare with expected hash
        Ok(derived_hash == expected_hash)
    }

    /// Compute verification hash for master key
    ///
    /// Returns SHA-256 hash of the master key for verification purposes
    fn compute_verification_hash(master_key: &MasterKey) -> [u8; 32] {
        let key_bytes = master_key.expose_secret();
        let mut hasher = Sha256::new();
        hasher.update(key_bytes);
        hasher.finalize().into()
    }

    /// Store verification hash for master key
    ///
    /// This should be called during initialization with the CORRECT master key.
    /// The hash is stored to disk and used to verify subsequent passphrase entries.
    pub fn store_verification_hash(&self, master_key: &MasterKey) -> Result<()> {
        let hash = Self::compute_verification_hash(master_key);
        std::fs::write(&self.verification_hash_path, &hash).map_err(|e| {
            SecurityError::Storage(format!("Failed to store verification hash: {}", e))
        })?;
        Ok(())
    }

    /// Verify master key against stored hash
    ///
    /// Returns true if the derived key matches the stored verification hash.
    /// This detects wrong passphrases before they pollute the cache.
    pub fn verify_master_key(&self, master_key: &MasterKey) -> Result<bool> {
        if !self.verification_hash_path.exists() {
            // No verification hash stored yet - cannot verify
            return Err(SecurityError::InvalidPassphrase(
                "Keystore not initialized. Run 'softkms init' first.".to_string(),
            ));
        }

        let stored_hash = std::fs::read(&self.verification_hash_path).map_err(|e| {
            SecurityError::Storage(format!("Failed to read verification hash: {}", e))
        })?;

        if stored_hash.len() != 32 {
            return Err(SecurityError::Storage(
                "Invalid verification hash file".to_string(),
            ));
        }

        let expected_hash = Self::compute_verification_hash(master_key);
        Ok(stored_hash.as_slice() == expected_hash.as_slice())
    }

    /// Get or derive master key
    ///
    /// If key exists in cache and is valid, returns cached key.
    /// Otherwise, prompts for passphrase and derives new key.
    pub fn get_master_key(&self, confirm: bool) -> Result<MasterKey> {
        // Check cache first
        {
            let cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;

            if let Some(key) = cache.get() {
                return Ok(MasterKey::from_secret(key));
            }
        }

        // Cache miss or expired - derive new key
        let passphrase = if confirm {
            master_key::prompt_passphrase_with_confirmation()?
        } else {
            master_key::prompt_passphrase()?
        };

        let master_key = MasterKey::derive(&passphrase, self.config.pbkdf2_iterations)?;

        // Cache the key
        {
            let mut cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;
            cache.store(master_key.to_secret());
        }

        Ok(master_key)
    }

    /// Derive master key from provided passphrase (non-interactive)
    ///
    /// Used when passphrase is provided via API (e.g., from CLI)
    ///
    /// SECURITY: Always derives key from provided passphrase and verifies
    /// against stored verification hash before caching. Wrong passphrase will fail.
    /// If verification_hash is None (init phase), allows any passphrase.
    pub fn derive_master_key(&self, passphrase: &str) -> Result<MasterKey> {
        // Derive key from provided passphrase
        let master_key = MasterKey::derive(passphrase, self.config.pbkdf2_iterations)?;
        let derived_hash = Self::compute_verification_hash(&master_key);

        // Check if we have an in-memory verification hash
        let has_in_memory_hash = {
            let guard = self
                .verification_hash
                .lock()
                .map_err(|_| SecurityError::LockPoisoned)?;
            guard.is_some()
        };

        if has_in_memory_hash {
            // We have a stored hash - verify the passphrase first
            let expected_hash = {
                let guard = self
                    .verification_hash
                    .lock()
                    .map_err(|_| SecurityError::LockPoisoned)?;
                guard.unwrap() // Safe because we just checked it's Some
            };

            tracing::debug!("Verifying passphrase against in-memory hash");
            tracing::debug!("Expected: {:?}", &expected_hash[..4]);
            tracing::debug!("Derived:  {:?}", &derived_hash[..4]);

            if derived_hash != expected_hash {
                return Err(SecurityError::InvalidPassphrase(
                    "Invalid passphrase. Please use the correct passphrase for this keystore."
                        .to_string(),
                ));
            }
        } else {
            // No in-memory hash - check if one exists on disk
            tracing::debug!(
                "No in-memory hash, checking disk at {:?}",
                self.verification_hash_path
            );
            if self.verification_hash_path.exists() {
                tracing::debug!("Hash file exists on disk, loading...");
                // Load and verify against disk hash
                let stored_hash = std::fs::read(&self.verification_hash_path).map_err(|e| {
                    SecurityError::Storage(format!("Failed to read verification hash: {}", e))
                })?;

                if stored_hash.len() != 32 {
                    return Err(SecurityError::Storage(
                        "Invalid verification hash file".to_string(),
                    ));
                }

                let mut expected_hash = [0u8; 32];
                expected_hash.copy_from_slice(&stored_hash);

                tracing::debug!("Expected hash from disk: {:?}", &expected_hash[..4]);
                tracing::debug!("Derived hash:           {:?}", &derived_hash[..4]);

                if derived_hash != expected_hash {
                    return Err(SecurityError::InvalidPassphrase(
                        "Invalid passphrase. Please use the correct passphrase for this keystore."
                            .to_string(),
                    ));
                }

                tracing::debug!("Passphrase verified successfully!");

                // Also store in memory for future validations
                let mut guard = self
                    .verification_hash
                    .lock()
                    .map_err(|_| SecurityError::LockPoisoned)?;
                *guard = Some(expected_hash);
            } else {
                tracing::debug!("No hash file on disk - allowing any passphrase (init phase)");
            }
        }

        // Verification passed (or init phase) - cache the key
        {
            let mut cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;
            cache.store(master_key.to_secret());
        }

        Ok(master_key)
    }

    /// Initialize with passphrase and store verification hash
    ///
    /// This is used during keystore initialization. It derives the master key
    /// from the passphrase and stores a verification hash on disk and in memory.
    pub fn init_with_passphrase(&self, passphrase: &str) -> Result<MasterKey> {
        // Derive key from passphrase
        let master_key = MasterKey::derive(passphrase, self.config.pbkdf2_iterations)?;

        // Compute and store verification hash of the CORRECT key (both disk and memory)
        let hash = Self::compute_verification_hash(&master_key);
        self.store_verification_hash(&master_key)?;
        self.set_verification_hash(hash);

        // Cache the verified key
        {
            let mut cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;
            cache.store(master_key.to_secret());
        }

        Ok(master_key)
    }

    /// Create a key wrapper for encryption/decryption
    pub fn create_wrapper(&self, master_key: &MasterKey) -> KeyWrapper {
        KeyWrapper::new(master_key.clone())
    }

    /// Get the cached master key
    ///
    /// Returns the cached master key if available, or error if not initialized.
    /// This should be used by KeyService operations after daemon is initialized.
    pub fn get_cached_master_key(&self) -> Result<MasterKey> {
        let cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;
        if let Some(key) = cache.get() {
            Ok(MasterKey::from_secret(key))
        } else {
            Err(SecurityError::InvalidPassphrase(
                "Keystore not initialized. Run 'softkms init' first.".to_string(),
            ))
        }
    }

    /// Change passphrase
    ///
    /// Re-encrypts all keys with new passphrase. This operation:
    /// 1. Prompts for old passphrase
    /// 2. Unwraps all existing keys
    /// 3. Prompts for new passphrase (with confirmation)
    /// 4. Re-wraps all keys
    /// 5. Updates cache with new master key
    pub fn change_passphrase<F>(
        &self,
        keys: &mut [(WrappedKey, Vec<u8>)], // (wrapped_key, aad)
        progress: F,
    ) -> Result<()>
    where
        F: Fn(usize, usize),
    {
        // Get old master key
        let old_key = self.get_master_key(false)?;
        let old_wrapper = self.create_wrapper(&old_key);

        // Unwrap all keys
        let mut plaintexts = Vec::new();
        for (i, (wrapped, aad)) in keys.iter().enumerate() {
            let plaintext = old_wrapper.unwrap(wrapped, aad)?;
            plaintexts.push(plaintext);
            progress(i + 1, keys.len());
        }

        // Prompt for new passphrase
        let new_passphrase = master_key::prompt_passphrase_with_confirmation()?;
        let new_key = MasterKey::derive(&new_passphrase, self.config.pbkdf2_iterations)?;
        let new_wrapper = self.create_wrapper(&new_key);

        // Re-wrap all keys
        let total = keys.len();
        for i in 0..total {
            let plaintext = &plaintexts[i];
            let (ref mut wrapped, ref aad) = keys[i];
            *wrapped = new_wrapper.wrap(plaintext, aad)?;
            progress(i + 1, total);
        }

        // Update cache
        {
            let mut cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;
            cache.store(new_key.to_secret());
        }

        Ok(())
    }

    /// Clear cache (e.g., on logout)
    pub fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.lock().map_err(|_| SecurityError::LockPoisoned)?;
        cache.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_validity() {
        let mut cache = MasterKeyCache::new(Duration::from_secs(300));
        assert!(!cache.is_valid());

        let key = Secret::new([0u8; 32]);
        cache.store(key);
        assert!(cache.is_valid());
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = MasterKeyCache::new(Duration::from_millis(1));
        let key = Secret::new([0u8; 32]);
        cache.store(key);
        assert!(cache.is_valid());

        std::thread::sleep(Duration::from_millis(10));
        assert!(!cache.is_valid());
    }
}
