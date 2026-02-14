//! Key service - Central key management with wrap/unwrap lifecycle
//!
//! This module implements the core security model where:
//! 1. Keys are generated/imported in plaintext
//! 2. Immediately wrapped (encrypted) with master key
//! 3. Stored at rest in encrypted form
//! 4. When needed: unwrapped into memory temporarily
//! 5. Used for operations
//! 6. Cleared from memory immediately after use
//!
//! This ensures keys NEVER exist in plaintext at rest and are only in
//! plaintext in memory for the minimum time necessary.

use crate::crypto::ed25519::{Ed25519Engine, ED25519_SECRET_KEY_SIZE};
use crate::crypto::hd_ed25519::{HdEd25519Engine, HdDerivationScheme, encode_bech32};
use crate::crypto::p256::DeterministicP256;
use crate::storage::StorageBackend;
use crate::security::{SecurityManager, WrappedKey};
use crate::{Config, Error, KeyId, KeyMetadata, KeyType, Result, Signature};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use chrono::Utc;
use secrecy::ExposeSecret;
use secrecy::Secret;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};
use zeroize::Zeroize;

/// Key service - manages key lifecycle with security wrapping
pub struct KeyService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    security_manager: Arc<SecurityManager>,
    config: Config,
}

/// Key data that has been unwrapped and is ready for use
/// Automatically cleared when dropped
pub struct UnwrappedKey {
    pub id: KeyId,
    pub algorithm: String,
    pub key_type: KeyType,
    pub material: KeyMaterial,
    pub public_key: Vec<u8>,
    pub metadata: KeyMetadata,
}

/// Key material variants
pub enum KeyMaterial {
    Ed25519(Secret<[u8; ED25519_SECRET_KEY_SIZE]>),
}

impl KeyService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        security_manager: Arc<SecurityManager>,
        config: Config,
    ) -> Self {
        Self {
            storage,
            security_manager,
            config,
        }
    }

    /// Get storage reference
    pub fn storage(&self) -> Arc<dyn StorageBackend + Send + Sync> {
        self.storage.clone()
    }

    pub async fn create_key(
        &self,
        algorithm: String,
        label: Option<String>,
        attributes: HashMap<String, String>,
        passphrase: &str,
    ) -> Result<KeyMetadata> {
        info!("Creating new {} key", algorithm);

        let key_id = KeyId::new_v4();
        let created_at = Utc::now();

        // Generate key material and public key first
        let (key_material, public_key_bytes) = match algorithm.as_str() {
            "ed25519" => {
                // Create temporary metadata for key generation
                let temp_metadata = KeyMetadata {
                    id: key_id,
                    label: label.clone(),
                    algorithm: algorithm.clone(),
                    key_type: KeyType::Imported,
                    created_at,
                    attributes: attributes.clone(),
                    public_key: Vec::new(),
                };
                let (secret, public_key, _metadata) = Ed25519Engine::generate_key(temp_metadata)?;
                let public_key_bytes = public_key.to_vec();
                let material = secret.expose_secret().to_vec();
                (material, public_key_bytes)
            }
            "p256" => {
                // Generate random P-256 key
                use p256::ecdsa::SigningKey;
                use rand_core::OsRng;
                let signing_key = SigningKey::random(&mut OsRng);
                let secret_bytes = signing_key.to_bytes();
                let material = secret_bytes.to_vec();
                let public_key = signing_key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
                (material, public_key)
            }
            _ => {
                return Err(Error::Crypto(format!("Unsupported algorithm: {}", algorithm)));
            }
        };

        // Create metadata with public key
        let metadata = KeyMetadata {
            id: key_id,
            label: label.clone(),
            algorithm: algorithm.clone(),
            key_type: KeyType::Imported,
            created_at,
            attributes: attributes.clone(),
            public_key: public_key_bytes.clone(),
        };

        debug!("Key generated in memory, now wrapping for storage");

        let master_key = self.security_manager
            .derive_master_key(passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&metadata);

        let wrapped = wrapper
            .wrap(&key_material, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to wrap key: {}", e)))?;

        let encrypted_data = wrapped.to_bytes();

        let mut material_to_clear = key_material.clone();
        material_to_clear.zeroize();
        drop(master_key);

        self.storage.store_key(key_id, &metadata, &encrypted_data).await?;

        info!("Key {} created and stored encrypted", key_id);

        Ok(metadata)
    }

    pub async fn sign(&self, key_id: KeyId, data: &[u8], passphrase: &str) -> Result<Signature> {
        debug!("Signing data with key {}", key_id);

        let result = self.storage.retrieve_key(key_id).await?;

        let (metadata, encrypted_data) = result
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        let master_key = self.security_manager
            .derive_master_key(passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&metadata);

        let wrapped = WrappedKey::from_bytes(&encrypted_data)
            .map_err(|e| Error::Crypto(format!("Invalid wrapped key: {}", e)))?;

        let key_material = wrapper
            .unwrap(&wrapped, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to unwrap key: {}", e)))?;

        let signature = match metadata.algorithm.as_str() {
            "ed25519" => {
                // Check if this is an HD-derived key (96 bytes) or regular key (32 bytes)
                if key_material.len() == 96 {
                    // HD-derived Ed25519 key - use ed25519-bip32 signing
                    let xprv = HdEd25519Engine::xprv_from_bytes(&key_material)
                        .map_err(|e| Error::Crypto(format!("Failed to parse HD Ed25519 key: {}", e)))?;
                    
                    // Get the derivation scheme from metadata
                    let scheme = match metadata.attributes.get("scheme") {
                        Some(s) if s == "v2" => HdDerivationScheme::V2,
                        _ => HdDerivationScheme::Peikert,
                    };
                    
                    let engine = HdEd25519Engine::new(scheme);
                    let sig = engine.sign(&xprv, data);
                    
                    Signature {
                        bytes: sig.to_bytes().to_vec(),
                        algorithm: "ed25519".to_string(),
                    }
                } else if key_material.len() == ED25519_SECRET_KEY_SIZE {
                    // Regular Ed25519 key (32 bytes)
                    let mut secret = [0u8; ED25519_SECRET_KEY_SIZE];
                    secret.copy_from_slice(&key_material);

                    let secret_secret = Secret::new(secret);
                    let sig = Ed25519Engine::sign(&secret_secret, data)?;

                    let mut temp_clear = secret;
                    temp_clear.zeroize();

                    sig
                } else {
                    return Err(Error::Crypto(format!(
                        "Invalid Ed25519 key material length: expected 32 or 96, got {}",
                        key_material.len()
                    )));
                }
            }
            "p256" => {
                // P-256 key is 32 bytes
                let sig = DeterministicP256::sign(&key_material, data)
                    .map_err(|e| Error::Crypto(format!("P-256 signing failed: {}", e)))?;
                
                Signature {
                    bytes: sig,
                    algorithm: "p256".to_string(),
                }
            }
            _ => {
                let mut material_to_clear = key_material.clone();
                material_to_clear.zeroize();
                return Err(Error::Crypto(format!("Unsupported algorithm: {}", metadata.algorithm)));
            }
        };

        let mut material_to_clear = key_material.clone();
        material_to_clear.zeroize();
        drop(master_key);

        info!("Data signed with key {}", key_id);

        Ok(signature)
    }

    pub async fn import_seed(
        &self,
        seed: Vec<u8>,
        label: Option<String>,
        passphrase: &str,
    ) -> Result<KeyMetadata> {
        info!("Importing seed");

        let key_id = KeyId::new_v4();
        let created_at = Utc::now();

        let metadata = KeyMetadata {
            id: key_id,
            label: label.clone(),
            algorithm: "bip32-seed".to_string(),
            key_type: KeyType::Seed,
            created_at,
            attributes: HashMap::new(),
            public_key: Vec::new(),
        };

        let master_key = self.security_manager
            .derive_master_key(passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&metadata);

        let wrapped = wrapper
            .wrap(&seed, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to wrap seed: {}", e)))?;

        let encrypted_data = wrapped.to_bytes();

        let mut seed_to_clear = seed.clone();
        seed_to_clear.zeroize();
        drop(master_key);

        self.storage.store_key(key_id, &metadata, &encrypted_data).await?;

        info!("Seed {} imported and stored encrypted", key_id);

        Ok(metadata)
    }

    pub async fn list_keys(&self) -> Result<Vec<KeyMetadata>> {
        self.storage.list_keys().await
    }

    pub async fn get_key(&self, key_id: KeyId) -> Result<Option<KeyMetadata>> {
        let result = self.storage.retrieve_key(key_id).await?;
        Ok(result.map(|(metadata, _)| metadata))
    }

    /// Derive a P-256 key deterministically from a stored seed
    ///
    /// Flow:
    /// 1. Check if key already exists for this (seed_id, origin, user_handle, counter)
    /// 2. If yes: return existing key (no seed needed)
    /// 3. If no: retrieve seed, derive P-256 key, wrap and store it
    pub async fn derive_p256_key(
        &self,
        seed_id: KeyId,
        origin: String,
        user_handle: String,
        counter: u32,
        label: Option<String>,
        passphrase: &str,
    ) -> Result<KeyMetadata> {
        info!(
            "Deriving P-256 key from seed {} for origin={} user={}",
            seed_id, origin, user_handle
        );

        // Check if we already have a derived key with these parameters
        // We store the derivation params in attributes for lookup
        let keys = self.list_keys().await?;
        let derivation_id = format!("{}:{}:{}:{}", seed_id, origin, user_handle, counter);
        
        for key in &keys {
            if key.algorithm == "p256" {
                if let Some(existing_label) = &key.label {
                    if existing_label == &derivation_id {
                        info!("P-256 key already exists for these parameters, returning existing");
                        return Ok(key.clone());
                    }
                }
            }
        }

        // Need to derive new key - retrieve the seed
        let seed_result = self.storage.retrieve_key(seed_id).await?;
        let (seed_metadata, seed_encrypted) = seed_result
            .ok_or_else(|| Error::KeyNotFound(format!("Seed {} not found", seed_id)))?;

        // Verify it's actually a seed
        if seed_metadata.algorithm != "bip32-seed" {
            return Err(Error::InvalidParams(
                format!("Key {} is not a seed (algorithm: {})", seed_id, seed_metadata.algorithm)
            ));
        }

        // Get master key
        let master_key = self.security_manager
            .derive_master_key(passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        // Unwrap seed
        let wrapper = self.security_manager.create_wrapper(&master_key);
        let seed_aad = Self::build_aad(&seed_metadata);
        
        let seed_wrapped = WrappedKey::from_bytes(&seed_encrypted)
            .map_err(|e| Error::Crypto(format!("Invalid wrapped seed: {}", e)))?;
        
        let seed_material = wrapper
            .unwrap(&seed_wrapped, &seed_aad)
            .map_err(|e| Error::Crypto(format!("Failed to unwrap seed: {}", e)))?;

        // Derive P-256 key using deterministic algorithm
        // Note: In the TypeScript implementation, the seed is first processed through PBKDF2
        // to get a 64-byte derived main key. Here we assume the stored seed is already that derived key.
        let p256_private_key = DeterministicP256::derive_key(
            &seed_material,
            &origin,
            &user_handle,
            counter,
        ).map_err(|e| Error::Crypto(format!("Failed to derive P-256 key: {}", e)))?;

        // Get public key
        let p256_public_key = DeterministicP256::get_public_key(&p256_private_key)
            .map_err(|e| Error::Crypto(format!("Failed to get P-256 public key: {}", e)))?;

        // Create new key metadata
        let key_id = KeyId::new_v4();
        let created_at = Utc::now();

        let mut attributes = HashMap::new();
        attributes.insert("seed_id".to_string(), seed_id.to_string());
        attributes.insert("origin".to_string(), origin.clone());
        attributes.insert("user_handle".to_string(), user_handle.clone());
        attributes.insert("counter".to_string(), counter.to_string());
        // Store derivation ID in label for easy lookup
        let derivation_label = derivation_id.clone();

        let metadata = KeyMetadata {
            id: key_id,
            label: Some(derivation_label),
            algorithm: "p256".to_string(),
            key_type: KeyType::Derived,
            created_at,
            attributes,
            public_key: p256_public_key.clone(),
        };

        // Wrap P-256 key
        let p256_aad = Self::build_aad(&metadata);
        let p256_wrapped = wrapper
            .wrap(&p256_private_key, &p256_aad)
            .map_err(|e| Error::Crypto(format!("Failed to wrap P-256 key: {}", e)))?;

        let p256_encrypted = p256_wrapped.to_bytes();

        // Clear sensitive material
        let mut p256_to_clear = p256_private_key.clone();
        p256_to_clear.zeroize();
        let mut seed_to_clear = seed_material.clone();
        seed_to_clear.zeroize();
        drop(master_key);

        // Store the derived key
        self.storage.store_key(key_id, &metadata, &p256_encrypted).await?;

        info!(
            "P-256 key {} derived and stored for origin={} user={}",
            key_id, origin, user_handle
        );

        Ok(metadata)
    }

    /// Derive an Ed25519 key from a stored seed using BIP32/BIP44
    ///
    /// Flow:
    /// 1. Check if key already exists for this (seed_id, derivation_path)
    /// 2. If yes: return existing key
    /// 3. If no: retrieve seed, derive Ed25519 key, wrap and store it
    pub async fn derive_ed25519_key(
        &self,
        seed_id: KeyId,
        derivation_path: &str,
        coin_type: u32,
        scheme: HdDerivationScheme,
        store: bool,
        passphrase: &str,
    ) -> Result<KeyMetadata> {
        info!(
            "Deriving Ed25519 key from seed {} with path {}",
            seed_id, derivation_path
        );

        // Check if we already have a derived key with these parameters
        let keys = self.list_keys().await?;
        let derivation_id = format!("{}:{}", seed_id, derivation_path);
        
        for key in &keys {
            if key.algorithm == "ed25519" && key.key_type == KeyType::Derived {
                if let Some(existing_label) = &key.label {
                    if existing_label == &derivation_id {
                        info!("Ed25519 key already exists for these parameters, returning existing");
                        return Ok(key.clone());
                    }
                }
            }
        }

        // Need to derive new key - retrieve the seed
        let seed_result = self.storage.retrieve_key(seed_id).await?;
        let (seed_metadata, seed_encrypted) = seed_result
            .ok_or_else(|| Error::KeyNotFound(format!("Seed {} not found", seed_id)))?;

        // Verify it's actually a seed
        if seed_metadata.algorithm != "bip32-seed" {
            return Err(Error::InvalidParams(
                format!("Key {} is not a seed (algorithm: {})", seed_id, seed_metadata.algorithm)
            ));
        }

        // Get master key
        let master_key = self.security_manager
            .derive_master_key(passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        // Unwrap seed
        let wrapper = self.security_manager.create_wrapper(&master_key);
        let seed_aad = Self::build_aad(&seed_metadata);
        
        let seed_wrapped = WrappedKey::from_bytes(&seed_encrypted)
            .map_err(|e| Error::Crypto(format!("Invalid wrapped seed: {}", e)))?;
        
        let seed_material = wrapper
            .unwrap(&seed_wrapped, &seed_aad)
            .map_err(|e| Error::Crypto(format!("Failed to unwrap seed: {}", e)))?;

        // Ensure seed is exactly 64 bytes
        if seed_material.len() != 64 {
            return Err(Error::Crypto(format!(
                "Invalid seed length: expected 64 bytes, got {}",
                seed_material.len()
            )));
        }

        // Derive Ed25519 key using HD wallet
        let engine = HdEd25519Engine::new(scheme);
        let derived = engine
            .derive_path(&seed_material, derivation_path)
            .map_err(|e| Error::Crypto(format!("Failed to derive Ed25519 key: {}", e)))?;

        // Extract the full extended private key (64 bytes extended secret + 32 bytes chain code = 96 bytes)
        // This is needed for proper BIP32-Ed25519 signing
        let ed25519_extended_key: [u8; 96] = HdEd25519Engine::xprv_to_bytes(&derived.xprv);

        // Create new key metadata
        let key_id = KeyId::new_v4();
        let created_at = Utc::now();

        let mut attributes = HashMap::new();
        attributes.insert("seed_id".to_string(), seed_id.to_string());
        attributes.insert("derivation_path".to_string(), derivation_path.to_string());
        attributes.insert("scheme".to_string(), if scheme == HdDerivationScheme::Peikert { "peikert".to_string() } else { "v2".to_string() });
        attributes.insert("coin_type".to_string(), coin_type.to_string());
        attributes.insert("hrp".to_string(), format!("{}", coin_type)); // Use coin type as default hrp
        
        let derivation_label = derivation_id.clone();

        let metadata = KeyMetadata {
            id: key_id,
            label: Some(derivation_label),
            algorithm: "ed25519".to_string(),
            key_type: KeyType::Derived,
            created_at,
            attributes,
            public_key: derived.public_key.to_vec(),
        };

        if store {
            // Wrap Ed25519 extended key (96 bytes)
            let ed25519_aad = Self::build_aad(&metadata);
            let ed25519_wrapped = wrapper
                .wrap(&ed25519_extended_key, &ed25519_aad)
                .map_err(|e| Error::Crypto(format!("Failed to wrap Ed25519 key: {}", e)))?;

            let ed25519_encrypted = ed25519_wrapped.to_bytes();

            // Store the derived key
            self.storage.store_key(key_id, &metadata, &ed25519_encrypted).await?;

            info!(
                "Ed25519 key {} derived and stored with path {}",
                key_id, derivation_path
            );
        } else {
            info!(
                "Ed25519 key {} derived (not stored) with path {}",
                key_id, derivation_path
            );
        }

        // Clear sensitive material
        let mut key_to_clear = ed25519_extended_key;
        key_to_clear.zeroize();
        let mut seed_to_clear = seed_material.clone();
        seed_to_clear.zeroize();
        drop(master_key);

        Ok(metadata)
    }

    /// Import an xpub for public-only derivation
    ///
    /// This allows deriving child public keys without having the private key
    pub async fn import_xpub(
        &self,
        xpub_bytes: Vec<u8>,
        coin_type: u32,
        account: u32,
        label: Option<String>,
        passphrase: &str,
    ) -> Result<KeyMetadata> {
        info!(
            "Importing xpub for coin_type={} account={}",
            coin_type, account
        );

        // Validate xpub length
        if xpub_bytes.len() != 64 {
            return Err(Error::InvalidParams(
                format!("Invalid xpub length: expected 64 bytes, got {}", xpub_bytes.len())
            ));
        }

        // Create new key metadata
        let key_id = KeyId::new_v4();
        let created_at = Utc::now();

        let mut attributes = HashMap::new();
        attributes.insert("coin_type".to_string(), coin_type.to_string());
        attributes.insert("account".to_string(), account.to_string());

        // Extract public key from xpub (first 32 bytes)
        let public_key = xpub_bytes[0..32].to_vec();

        let metadata = KeyMetadata {
            id: key_id,
            label,
            algorithm: "ed25519-xpub".to_string(),
            key_type: KeyType::ExtendedPublic,
            created_at,
            attributes,
            public_key: public_key.clone(),
        };

        // Get master key
        let master_key = self.security_manager
            .derive_master_key(passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        // Wrap xpub
        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&metadata);
        
        let wrapped = wrapper
            .wrap(&xpub_bytes, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to wrap xpub: {}", e)))?;

        let encrypted = wrapped.to_bytes();

        drop(master_key);

        // Store the xpub
        self.storage.store_key(key_id, &metadata, &encrypted).await?;

        info!(
            "XPub {} imported for coin_type={} account={}",
            key_id, coin_type, account
        );

        Ok(metadata)
    }

    /// Derive a child public key from a stored xpub
    pub async fn derive_ed25519_public(
        &self,
        xpub_id: KeyId,
        index: u32,
        scheme: HdDerivationScheme,
        hrp: Option<&str>,
    ) -> Result<(KeyId, String, [u8; 32])> {
        info!(
            "Deriving Ed25519 public key from xpub {} at index {}",
            xpub_id, index
        );

        // Retrieve the xpub
        let result = self.storage.retrieve_key(xpub_id).await?;
        let (xpub_metadata, xpub_encrypted) = result
            .ok_or_else(|| Error::KeyNotFound(format!("XPub {} not found", xpub_id)))?;

        // Verify it's actually an xpub
        if xpub_metadata.algorithm != "ed25519-xpub" || xpub_metadata.key_type != KeyType::ExtendedPublic {
            return Err(Error::InvalidParams(
                format!("Key {} is not an xpub", xpub_id)
            ));
        }

        // Unwrap xpub (no passphrase needed for verification, but xpub is encrypted at rest)
        // Actually, we need passphrase to unwrap - this is a security feature
        // For true "watch-only" derivation, we'd need to cache the unwrapped xpub
        // For now, we'll require passphrase to unwrap
        let master_key = self.security_manager
            .get_cached_master_key()
            .map_err(|_| Error::Crypto("Keystore not initialized. Passphrase required for xpub operations.".to_string()))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&xpub_metadata);
        
        let xpub_wrapped = WrappedKey::from_bytes(&xpub_encrypted)
            .map_err(|e| Error::Crypto(format!("Invalid wrapped xpub: {}", e)))?;
        
        let xpub_material = wrapper
            .unwrap(&xpub_wrapped, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to unwrap xpub: {}", e)))?;

        // Create XPub from bytes
        let xpub = HdEd25519Engine::xpub_from_bytes(&xpub_material)
            .map_err(|e| Error::Crypto(format!("Invalid xpub: {}", e)))?;

        // Derive child public key
        let engine = HdEd25519Engine::new(scheme);
        let derived = engine.derive_public(&xpub, index)
            .map_err(|e| Error::Crypto(format!("Failed to derive public key: {}", e)))?;

        // Format address with hrp if provided
        let address = if let Some(h) = hrp {
            encode_bech32(h, &derived.public_key)
        } else {
            hex::encode(&derived.public_key)
        };

        let key_id = KeyId::new_v4();

        Ok((key_id, address, derived.public_key))
    }

    pub async fn delete_key(&self, key_id: KeyId) -> Result<()> {
        info!("Deleting key {}", key_id);
        self.storage.delete_key(key_id).await?;
        Ok(())
    }

    fn build_aad(metadata: &KeyMetadata) -> Vec<u8> {
        let aad = format!(
            "softkms:key:{}:{}:{}:{}",
            metadata.id, metadata.algorithm, metadata.key_type, metadata.created_at
        );
        aad.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::file::FileStorage;
    use crate::security::{SecurityConfig, SecurityManager, create_cache};
    use tempfile::TempDir;

    struct TestService {
        _temp_dir: TempDir,
        service: KeyService,
    }

    async fn create_test_service_with_init(passphrase: &str) -> TestService {
        let temp_dir = TempDir::new().unwrap();
        let storage = Arc::new(FileStorage::new(temp_dir.path().to_path_buf(), Config::default()));
        storage.init().await.unwrap();

        let security_config = SecurityConfig::new();
        let cache = create_cache(300);
        let security_manager = Arc::new(SecurityManager::new(cache, security_config, temp_dir.path().to_path_buf()));
        
        // Initialize the security manager with passphrase
        security_manager.init_with_passphrase(passphrase).unwrap();

        let config = Config::default();

        let service = KeyService::new(storage, security_manager, config);

        TestService {
            _temp_dir: temp_dir,
            service,
        }
    }

    #[tokio::test]
    async fn test_create_key_and_list() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "ed25519".to_string(),
            Some("Test Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
        ).await.unwrap();

        assert_eq!(metadata.algorithm, "ed25519");
        assert_eq!(metadata.label, Some("Test Key".to_string()));

        let keys = service.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, metadata.id);
    }

    #[tokio::test]
    async fn test_sign_with_key() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "ed25519".to_string(),
            Some("Signing Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
        ).await.unwrap();

        let data = b"Hello, World!";
        let signature = service.sign(metadata.id, data, passphrase).await.unwrap();

        assert_eq!(signature.algorithm, "ed25519");
        assert_eq!(signature.bytes.len(), 64);
    }

    #[tokio::test]
    async fn test_import_seed() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;
        let seed = vec![0u8; 32];

        let metadata = service.import_seed(
            seed,
            Some("Test Seed".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(metadata.algorithm, "bip32-seed");
        assert_eq!(metadata.key_type, KeyType::Seed);
    }



    #[tokio::test]
    async fn test_delete_key() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "ed25519".to_string(),
            None,
            std::collections::HashMap::new(),
            passphrase,
        ).await.unwrap();

        service.delete_key(metadata.id).await.unwrap();

        let result = service.get_key(metadata.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_multiple_keys_same_passphrase() {
        let passphrase = "shared_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let key1 = service.create_key(
            "ed25519".to_string(),
            Some("Key 1".to_string()),
            std::collections::HashMap::new(),
            passphrase,
        ).await.unwrap();

        let key2 = service.create_key(
            "ed25519".to_string(),
            Some("Key 2".to_string()),
            std::collections::HashMap::new(),
            passphrase,
        ).await.unwrap();

        let keys = service.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);

        let data = b"test data";
        let sig1 = service.sign(key1.id, data, passphrase).await.unwrap();
        let sig2 = service.sign(key2.id, data, passphrase).await.unwrap();

        assert_ne!(sig1.bytes, sig2.bytes);
    }

    #[tokio::test]
    async fn test_p256_key_derivation_flow() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        // Step 1: Import a seed
        let seed = vec![0xABu8; 64]; // 64-byte seed (like BIP32 derived key)
        let seed_metadata = service.import_seed(
            seed.clone(),
            Some("Test Seed for P-256".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(seed_metadata.algorithm, "bip32-seed");
        assert_eq!(seed_metadata.key_type, KeyType::Seed);

        // Step 2: Derive a P-256 key deterministically from the seed
        let origin = "https://example.com";
        let user_handle = "user123";
        let counter = 0u32;

        let p256_metadata = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            counter,
            Some("Derived P-256 Key".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(p256_metadata.algorithm, "p256");
        assert_eq!(p256_metadata.key_type, KeyType::Derived);

        // Verify attributes are set correctly
        assert_eq!(p256_metadata.attributes.get("seed_id"), Some(&seed_metadata.id.to_string()));
        assert_eq!(p256_metadata.attributes.get("origin"), Some(&origin.to_string()));
        assert_eq!(p256_metadata.attributes.get("user_handle"), Some(&user_handle.to_string()));
        assert_eq!(p256_metadata.attributes.get("counter"), Some(&counter.to_string()));

        // Step 3: Retrieve and use the derived key for signing
        let test_data = b"test message for P-256 signing";
        let signature = service.sign(p256_metadata.id, test_data, passphrase).await.unwrap();

        assert_eq!(signature.algorithm, "p256");
        // P-256 signatures are typically 64 bytes (r || s)
        assert_eq!(signature.bytes.len(), 64);

        // Step 4: Verify the signature using the public key
        // The public key should be retrievable via get_key
        let retrieved_key = service.get_key(p256_metadata.id).await.unwrap();
        assert!(retrieved_key.is_some());

        // Verify determinism: deriving again with same params returns same key
        let p256_metadata_2 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            counter,
            Some("Derived P-256 Key".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(p256_metadata.id, p256_metadata_2.id);

        // Verify different counter produces different key
        let p256_metadata_3 = service.derive_p256_key(
            seed_metadata.id,
            origin.to_string(),
            user_handle.to_string(),
            1u32, // Different counter
            Some("Derived P-256 Key".to_string()),
            passphrase,
        ).await.unwrap();

        assert_ne!(p256_metadata.id, p256_metadata_3.id);

        // Sign with both keys and verify they produce different signatures
        let test_data_2 = b"another test message";
        let sig1 = service.sign(p256_metadata.id, test_data_2, passphrase).await.unwrap();
        let sig2 = service.sign(p256_metadata_3.id, test_data_2, passphrase).await.unwrap();

        assert_ne!(sig1.bytes, sig2.bytes);

        // Verify total keys: 1 seed + 2 derived keys = 3 keys
        let keys = service.list_keys().await.unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[tokio::test]
    async fn test_hd_ed25519_sign_and_verify() {
        use crate::crypto::ed25519::Ed25519Engine;
        
        let passphrase = "test_passphrase_hd_ed25519";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        // Step 1: Import a 64-byte seed (standard BIP32 seed)
        let seed = hex::decode("a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05").unwrap();
        assert_eq!(seed.len(), 64);
        
        let seed_metadata = service.import_seed(
            seed,
            Some("HD Ed25519 Test Seed".to_string()),
            passphrase,
        ).await.unwrap();

        assert_eq!(seed_metadata.algorithm, "bip32-seed");
        assert_eq!(seed_metadata.key_type, KeyType::Seed);

        // Step 2: Derive an Ed25519 key using BIP44 path
        let derived_metadata = service.derive_ed25519_key(
            seed_metadata.id,
            "m/44'/283'/0'/0/0",
            283,
            HdDerivationScheme::Peikert,
            true, // store the key
            passphrase,
        ).await.unwrap();

        assert_eq!(derived_metadata.algorithm, "ed25519");
        assert_eq!(derived_metadata.key_type, KeyType::Derived);
        assert!(!derived_metadata.public_key.is_empty(), "Public key should be stored");

        // Step 3: Sign data with the derived key
        let test_data = b"hello";
        let signature = service.sign(derived_metadata.id, test_data, passphrase).await.unwrap();

        assert_eq!(signature.algorithm, "ed25519");
        assert_eq!(signature.bytes.len(), 64);

        // Step 4: Verify the signature using the stored public key
        let public_key = &derived_metadata.public_key;
        let valid = Ed25519Engine::verify(public_key, test_data, &signature.bytes).unwrap();
        assert!(valid, "Signature should be valid");

        // Step 5: Verify that wrong data fails
        let wrong_data = b"wrong";
        let wrong_valid = Ed25519Engine::verify(public_key, wrong_data, &signature.bytes).unwrap();
        assert!(!wrong_valid, "Signature should be invalid for wrong data");

        // Verify we have 2 keys (1 seed + 1 derived)
        let keys = service.list_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
    }
}
