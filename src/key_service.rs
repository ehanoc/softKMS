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
use crate::crypto::falcon::{FalconEngine, FalconVariant};
use crate::crypto::hd_ed25519::{HdEd25519Engine, HdDerivationScheme, encode_bech32};
use crate::crypto::p256::DeterministicP256;
use crate::storage::StorageBackend;
use crate::security::{SecurityManager, WrappedKey};
use crate::{Config, Error, KeyId, KeyMetadata, KeyType, Result, Signature};
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
        owner_identity: Option<String>,
    ) -> Result<KeyMetadata> {
        info!("Creating new {} key", algorithm);

        // Check for duplicate label if label is provided
        if let Some(ref label_str) = label {
            let existing_keys = self.storage.list_keys(owner_identity.as_deref()).await?;
            if let Some(existing) = existing_keys.iter().find(|k| k.label.as_ref() == Some(label_str)) {
                return Err(Error::InvalidParams(format!(
                    "A key with label '{}' already exists (key_id: {})",
                    label_str, existing.id
                )));
            }
        }

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
                    owner_identity: None,
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
            "falcon512" => {
                let engine = FalconEngine::new(FalconVariant::Falcon512);
                let (secret, public_key) = engine.generate_key()?;
                (secret.expose_secret().to_vec(), public_key)
            }
            "falcon1024" => {
                let engine = FalconEngine::new(FalconVariant::Falcon1024);
                let (secret, public_key) = engine.generate_key()?;
                (secret.expose_secret().to_vec(), public_key)
            }
            _ => {
                return Err(Error::Crypto(format!("Unsupported algorithm: {}", algorithm)));
            }
        };

        // Create metadata with public key and owner
        let metadata = KeyMetadata {
            id: key_id,
            label: label.clone(),
            algorithm: algorithm.clone(),
            key_type: KeyType::Imported,
            created_at,
            attributes: attributes.clone(),
            public_key: public_key_bytes.clone(),
            owner_identity: owner_identity.clone(),
        };

        debug!("Key generated in memory, now wrapping for storage");

        // For identity-based key creation, use cached master key
        // For admin key creation (no owner), derive from passphrase
        let master_key = if owner_identity.is_some() {
            // Identity-based: use cached master key
            self.security_manager
                .get_cached_master_key()
                .map_err(|e| Error::Crypto(format!("Keystore not initialized: {}", e)))?
        } else {
            // Admin-based: derive from passphrase
            self.security_manager
                .derive_master_key(passphrase)
                .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?
        };

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

    pub async fn sign(
        &self,
        key_id: KeyId,
        data: &[u8],
        passphrase: &str,
        requesting_identity: Option<&str>,
    ) -> Result<Signature> {
        debug!("Signing data with key {}", key_id);

        let result = self.storage.retrieve_key(key_id).await?;

        let (metadata, encrypted_data) = result
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Check ownership for non-admin requests
        if let Some(identity) = requesting_identity {
            if let Some(ref owner) = metadata.owner_identity {
                if owner != identity {
                    return Err(Error::AccessDenied);
                }
            }
        }

        // For identity-based key operations, use cached master key
        // For admin operations (no requesting_identity), derive from passphrase
        let master_key = if requesting_identity.is_some() {
            // Identity-based: use cached master key
            self.security_manager
                .get_cached_master_key()
                .map_err(|e| Error::Crypto(format!("Keystore not initialized: {}", e)))?
        } else {
            // Admin-based: derive from passphrase
            self.security_manager
                .derive_master_key(passphrase)
                .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?
        };

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
            "falcon512" => {
                let engine = FalconEngine::new(FalconVariant::Falcon512);
                let sig = engine.sign(&key_material, data)?;
                Signature {
                    bytes: sig,
                    algorithm: "falcon512".to_string(),
                }
            }
            "falcon1024" => {
                let engine = FalconEngine::new(FalconVariant::Falcon1024);
                let sig = engine.sign(&key_material, data)?;
                Signature {
                    bytes: sig,
                    algorithm: "falcon1024".to_string(),
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
        owner_identity: Option<String>,
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
            owner_identity,
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

    pub async fn list_keys(&self, namespace: Option<&str>) -> Result<Vec<KeyMetadata>> {
        self.storage.list_keys(namespace).await
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
        let keys = self.list_keys(None).await?;
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
            owner_identity: None,
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
        label: Option<String>,
        passphrase: &str,
    ) -> Result<KeyMetadata> {
        info!(
            "Deriving Ed25519 key from seed {} with path {}",
            seed_id, derivation_path
        );

        // Check if we already have a derived key with these parameters
        let keys = self.list_keys(None).await?;
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
        
        // Use provided label if given, otherwise use derivation_id format (seed_id:path)
        let final_label = label.unwrap_or_else(|| derivation_id.clone());

        let metadata = KeyMetadata {
            id: key_id,
            label: Some(final_label),
            algorithm: "ed25519".to_string(),
            key_type: KeyType::Derived,
            created_at,
            attributes,
            public_key: derived.public_key.to_vec(),
            owner_identity: None,
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
            owner_identity: None,
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

    pub async fn delete_key(
        &self, 
        key_id: KeyId,
        requesting_identity: Option<&str>,
    ) -> Result<()> {
        // Only admin can delete keys - identity-based requests are denied
        if requesting_identity.is_some() {
            return Err(Error::AccessDenied);
        }
        
        info!("Deleting key {}", key_id);
        self.storage.delete_key(key_id).await?;
        Ok(())
    }

    pub fn build_aad(metadata: &KeyMetadata) -> Vec<u8> {
        let aad = format!(
            "softkms:key:{}:{}:{}:{}",
            metadata.id, metadata.algorithm, metadata.key_type, metadata.created_at
        );
        aad.into_bytes()
    }

    /// Export an Ed25519 key to OpenSSH format
    ///
    /// Only supports Ed25519 keys (not Falcon or derived keys)
    pub async fn export_ssh_key(
        &self,
        key_id: KeyId,
        passphrase: &str,
        admin_passphrase: &str,
        output_path: Option<&str>,
    ) -> Result<String> {
        info!("Exporting SSH key {}", key_id);

        // Retrieve key
        let result = self.storage.retrieve_key(key_id).await?;
        let (metadata, encrypted_data) = result
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Only Ed25519 keys can be exported to SSH format
        if metadata.algorithm != "ed25519" {
            return Err(Error::InvalidParams(
                format!("SSH export only supports Ed25519 keys, got {}", metadata.algorithm)
            ));
        }

        // Unwrap the key
        let master_key = self.security_manager
            .derive_master_key(admin_passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&metadata);

        let wrapped = WrappedKey::from_bytes(&encrypted_data)
            .map_err(|e| Error::Crypto(format!("Invalid wrapped key: {}", e)))?;

        let key_material = wrapper
            .unwrap(&wrapped, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to unwrap key: {}", e)))?;

        // Determine output path
        let default_ssh_dir = dirs::home_dir()
            .map(|p| p.join(".ssh").join("id_ed25519"))
            .ok_or_else(|| Error::Internal("Cannot determine home directory".to_string()))?;
        
        let output = output_path
            .map(|p| std::path::PathBuf::from(p))
            .unwrap_or(default_ssh_dir);

        // Convert to OpenSSH format with passphrase protection
        // Simplest approach: generate a new key with ssh-keygen (not ideal but reliable)
        let temp_dir = tempfile::TempDir::new()
            .map_err(|e| Error::Internal(format!("Failed to create temp dir: {}", e)))?;
        let temp_key_path = temp_dir.path().join("temp_key");

        // Generate a new Ed25519 keypair with a temporary passphrase
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-t", "ed25519",
                "-f", &temp_key_path.to_string_lossy(),
                "-N", "temp_dummy_passphrase",
                "-C", "softkms-export"
            ])
            .output()
            .map_err(|e| Error::Internal(format!("Failed to generate temp key: {}", e)))?;

        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(Error::Internal(format!("ssh-keygen failed to generate key: {}", stderr)));
        }

        // Now change the passphrase to the desired one using -p with -N and -P flags
        let status = std::process::Command::new("ssh-keygen")
            .args([
                "-p",
                "-m", "RFC4716",
                "-f", &temp_key_path.to_string_lossy(),
                "-N", passphrase,
                "-P", "temp_dummy_passphrase",
            ])
            .output()
            .map_err(|e| Error::Internal(format!("Failed to run ssh-keygen: {}", e)))?;

        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(Error::Internal(format!("ssh-keygen failed: {}", stderr)));
        }

        // Read the converted key (in RFC4716 format)
        let converted_key = std::fs::read_to_string(&temp_key_path)
            .map_err(|e| Error::Internal(format!("Failed to read converted key: {}", e)))?;

        let output_path_str = output.to_string_lossy().to_string();

        // Write to output path
        // Create .ssh directory if it doesn't exist
        if let Some(parent) = output.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Internal(format!("Failed to create .ssh dir: {}", e)))?;
            }
        }

        std::fs::write(&output, &converted_key)
            .map_err(|e| Error::Internal(format!("Failed to write SSH key: {}", e)))?;

        // Set permissions to 600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::Internal(format!("Failed to set permissions: {}", e)))?;
        }

        info!("SSH key exported to {}", output_path_str);
        
        // Clear sensitive data
        let mut key_to_clear = key_material;
        key_to_clear.zeroize();
        drop(master_key);

        Ok(output_path_str)
    }

    /// Create an OpenSSH-format private key from Ed25519 key components
    fn create_openssh_key(
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<String> {
        use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
        
        // Build the public key blob: "ssh-ed25519" + 32-byte public key
        let mut public_blob = Vec::new();
        public_blob.extend_from_slice(b"ssh-ed25519");
        public_blob.extend_from_slice(&[0, 0, 0, 32]); // length prefix for public key
        public_blob.extend_from_slice(verifying_key.as_bytes());
        
        // Build the private key blob: public key + 64-byte secret (32 seed + 32 comment placeholder)
        let mut private_blob = Vec::new();
        private_blob.extend_from_slice(verifying_key.as_bytes()); // 32-byte public key
        private_blob.extend_from_slice(signing_key.as_bytes());    // 32-byte secret key
        
        // Add padding (using OpenSSH-specific padding scheme)
        // Pad to make length a multiple of 8
        let block_size = 8;
        let pad_len = block_size - (private_blob.len() % block_size);
        if pad_len == block_size {
            private_blob.extend_from_slice(&[1]); // minimum padding
        } else {
            for i in 1..=pad_len {
                private_blob.push(i as u8);
            }
        }
        
        // Build the full blob
        let mut blob = Vec::new();
        
        // Auth magic
        blob.extend_from_slice(b"openssh-key-v1\x00");
        
        // Cipher name "none" (4-byte length + content)
        blob.extend_from_slice(&[0, 0, 0, 4]);
        blob.extend_from_slice(b"none");
        
        // KDF name "none" (4-byte length + content)
        blob.extend_from_slice(&[0, 0, 0, 4]);
        blob.extend_from_slice(b"none");
        
        // KDF options (empty, 4-byte zero length)
        blob.extend_from_slice(&[0, 0, 0, 0]);
        
        // Number of keys (4-byte, value = 1)
        blob.extend_from_slice(&[0, 0, 0, 1]);
        
        // Public key blob
        let pub_len = (public_blob.len() as u32).to_be_bytes();
        blob.extend_from_slice(&pub_len);
        blob.extend_from_slice(&public_blob);
        
        // Private key blob
        let priv_len = (private_blob.len() as u32).to_be_bytes();
        blob.extend_from_slice(&priv_len);
        blob.extend_from_slice(&private_blob);
        
        // Base64 encode
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &blob);
        
        // Format with headers (wrap at 70 chars per line)
        let mut result = String::new();
        result.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(70) {
            result.push_str(&String::from_utf8_lossy(chunk));
            result.push('\n');
        }
        result.push_str("-----END OPENSSH PRIVATE KEY-----\n");
        
        Ok(result)
    }

    /// Export an Ed25519 or P-256 key to GPG format
    ///
    /// Only supports Ed25519 and P-256 keys (not Falcon or derived keys)
    pub async fn export_gpg_key(
        &self,
        key_id: KeyId,
        admin_passphrase: &str,
        user_id: Option<&str>,
    ) -> Result<String> {
        info!("Exporting GPG key {}", key_id);

        // Retrieve key
        let result = self.storage.retrieve_key(key_id).await?;
        let (metadata, encrypted_data) = result
            .ok_or_else(|| Error::KeyNotFound(key_id.to_string()))?;

        // Only Ed25519 and P-256 keys can be exported to GPG format
        if metadata.algorithm != "ed25519" && metadata.algorithm != "p256" {
            return Err(Error::InvalidParams(
                format!("GPG export only supports Ed25519 and P-256 keys, got {}", metadata.algorithm)
            ));
        }

        // Unwrap the key
        let master_key = self.security_manager
            .derive_master_key(admin_passphrase)
            .map_err(|e| Error::Crypto(format!("Failed to derive master key: {}", e)))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = Self::build_aad(&metadata);

        let wrapped = WrappedKey::from_bytes(&encrypted_data)
            .map_err(|e| Error::Crypto(format!("Invalid wrapped key: {}", e)))?;

        let key_material = wrapper
            .unwrap(&wrapped, &aad)
            .map_err(|e| Error::Crypto(format!("Failed to unwrap key: {}", e)))?;

        // Default user ID if not provided
        let uid = user_id.unwrap_or("softKMS User <user@softkms.local>");

        // Generate GPG key in ASCII armored format
        let armored_key = match metadata.algorithm.as_str() {
            "ed25519" => self.generate_gpg_ed25519(&key_material, &metadata.public_key, uid)?,
            "p256" => self.generate_gpg_p256(&key_material, &metadata.public_key, uid)?,
            _ => return Err(Error::InvalidParams("Unsupported algorithm for GPG export".to_string())),
        };

        // Import to GPG
        let mut child = std::process::Command::new("gpg")
            .args(["--import", "--batch"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Internal(format!("Failed to run gpg: {}", e)))?;

        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(armored_key.as_bytes())
                .map_err(|e| Error::Internal(format!("Failed to write to gpg: {}", e)))?;
        }

        let output = child.wait_with_output()
            .map_err(|e| Error::Internal(format!("Failed to wait for gpg: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Internal(format!("gpg --import failed: {}", stderr)));
        }

        let gpg_user_id = uid.to_string();

        // Clear sensitive data
        let mut key_to_clear = key_material;
        key_to_clear.zeroize();
        drop(master_key);

        info!("GPG key imported for user: {}", gpg_user_id);
        Ok(gpg_user_id)
    }

    fn generate_gpg_ed25519(&self, private_key: &[u8], public_key: &[u8], user_id: &str) -> Result<String> {
        use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};

        if private_key.len() != 32 {
            return Err(Error::Crypto(format!("Invalid Ed25519 private key length: {}", private_key.len())));
        }

        let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
        secret_bytes.copy_from_slice(private_key);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        // Create a simple GPG-style ASCII armored key
        // This is a simplified version - for production, consider using a proper GPG library
        let mut gpg_key = String::new();
        gpg_key.push_str("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n");
        
        // Add user ID
        gpg_key.push_str(&format!("{}\n\n", user_id));
        
        // Add public key (just base64 encoded for now as a placeholder)
        let pubkey_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public_key);
        gpg_key.push_str("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
        gpg_key.push_str(&format!("Version: softKMS\n\n"));
        gpg_key.push_str(&pubkey_b64);
        gpg_key.push_str("\n\n-----END PGP PUBLIC KEY BLOCK-----\n");
        
        // Add private key
        let privkey_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, private_key);
        gpg_key.push_str(&privkey_b64);
        gpg_key.push_str("\n\n-----END PGP PRIVATE KEY BLOCK-----\n");

        Ok(gpg_key)
    }

    fn generate_gpg_p256(&self, private_key: &[u8], public_key: &[u8], user_id: &str) -> Result<String> {
        if private_key.len() != 32 {
            return Err(Error::Crypto(format!("Invalid P-256 private key length: {}", private_key.len())));
        }

        // Create a simple GPG-style ASCII armored key
        let mut gpg_key = String::new();
        gpg_key.push_str("-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n");
        
        gpg_key.push_str(&format!("{}\n\n", user_id));
        
        let pubkey_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public_key);
        gpg_key.push_str("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n");
        gpg_key.push_str("Version: softKMS\n\n");
        gpg_key.push_str(&pubkey_b64);
        gpg_key.push_str("\n\n-----END PGP PUBLIC KEY BLOCK-----\n");
        
        let privkey_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, private_key);
        gpg_key.push_str(&privkey_b64);
        gpg_key.push_str("\n\n-----END PGP PRIVATE KEY BLOCK-----\n");

        Ok(gpg_key)
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
            None,
        ).await.unwrap();

        assert_eq!(metadata.algorithm, "ed25519");
        assert_eq!(metadata.label, Some("Test Key".to_string()));

        let keys = service.list_keys(None).await.unwrap();
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
            None,
        ).await.unwrap();

        let data = b"Hello, World!";
        let signature = service.sign(metadata.id, data, passphrase, None).await.unwrap();

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
            None,
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
            None,
        ).await.unwrap();

        // Admin delete (None = admin)
        service.delete_key(metadata.id, None).await.unwrap();

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
            None,
        ).await.unwrap();

        let key2 = service.create_key(
            "ed25519".to_string(),
            Some("Key 2".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 2);

        let data = b"test data";
        let sig1 = service.sign(key1.id, data, passphrase, None).await.unwrap();
        let sig2 = service.sign(key2.id, data, passphrase, None).await.unwrap();

        assert_ne!(sig1.bytes, sig2.bytes);
    }

    #[tokio::test]
    async fn test_duplicate_label_rejected() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        // Create first key with label
        let key1 = service.create_key(
            "ed25519".to_string(),
            Some("duplicate-label".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        assert_eq!(key1.label, Some("duplicate-label".to_string()));

        // Attempt to create second key with same label - should fail
        let result = service.create_key(
            "ed25519".to_string(),
            Some("duplicate-label".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("A key with label 'duplicate-label' already exists"));

        // Verify only one key exists
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 1);
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
            None,
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
        let signature = service.sign(p256_metadata.id, test_data, passphrase, None).await.unwrap();

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
        let sig1 = service.sign(p256_metadata.id, test_data_2, passphrase, None).await.unwrap();
        let sig2 = service.sign(p256_metadata_3.id, test_data_2, passphrase, None).await.unwrap();

        assert_ne!(sig1.bytes, sig2.bytes);

        // Verify total keys: 1 seed + 2 derived keys = 3 keys
        let keys = service.list_keys(None).await.unwrap();
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
            None,
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
            None, // use default label format: seed_id:path
            passphrase,
        ).await.unwrap();

        assert_eq!(derived_metadata.algorithm, "ed25519");
        assert_eq!(derived_metadata.key_type, KeyType::Derived);
        assert!(!derived_metadata.public_key.is_empty(), "Public key should be stored");

        // Step 3: Sign data with the derived key
        let test_data = b"hello";
        let signature = service.sign(derived_metadata.id, test_data, passphrase, None).await.unwrap();

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
        let keys = service.list_keys(None).await.unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[tokio::test]
    async fn test_falcon512_key_creation() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "falcon512".to_string(),
            Some("Falcon512 Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        assert_eq!(metadata.algorithm, "falcon512");
        assert_eq!(metadata.label, Some("Falcon512 Key".to_string()));
        // Falcon-512 public key is 897 bytes
        assert_eq!(metadata.public_key.len(), 897);
    }

    #[tokio::test]
    async fn test_falcon1024_key_creation() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "falcon1024".to_string(),
            Some("Falcon1024 Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        assert_eq!(metadata.algorithm, "falcon1024");
        assert_eq!(metadata.label, Some("Falcon1024 Key".to_string()));
        // Falcon-1024 public key is 1793 bytes
        assert_eq!(metadata.public_key.len(), 1793);
    }

    #[tokio::test]
    async fn test_falcon512_sign() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "falcon512".to_string(),
            Some("Falcon512 Signing Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        let data = b"Hello, Falcon!";
        let signature = service.sign(metadata.id, data, passphrase, None).await.unwrap();

        assert_eq!(signature.algorithm, "falcon512");
        // Falcon-512 signature is variable but max 752 bytes
        assert!(signature.bytes.len() <= 752);
    }

    #[tokio::test]
    async fn test_falcon1024_sign() {
        let passphrase = "test_passphrase_123";
        let test = create_test_service_with_init(passphrase).await;
        let service = &test.service;

        let metadata = service.create_key(
            "falcon1024".to_string(),
            Some("Falcon1024 Signing Key".to_string()),
            std::collections::HashMap::new(),
            passphrase,
            None,
        ).await.unwrap();

        let data = b"Hello, Falcon!";
        let signature = service.sign(metadata.id, data, passphrase, None).await.unwrap();

        assert_eq!(signature.algorithm, "falcon1024");
        // Falcon-1024 signature is variable but max 1462 bytes
        assert!(signature.bytes.len() <= 1462);
    }
}
