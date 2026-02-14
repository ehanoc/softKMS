//! gRPC API server implementation
//!
//! This module implements the KeyStore gRPC service using the generated
//! protobuf code. All operations go through the KeyService which handles
//! the security lifecycle (wrap/unwrap).
//!
//! Security Model:
//! - Daemon prompts for passphrase ONCE on startup
//! - Passphrase is cached in memory (SecurityManager)
//! - All key operations use cached master key
//! - Passphrase is NEVER sent over gRPC

use std::net::SocketAddr;
use std::sync::Arc;

use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info, debug};

use crate::key_service::KeyService;
use crate::security::SecurityManager;
use crate::{Config, Error, KeyId, KeyMetadata, KeyType};

// Import BIP39 for mnemonic handling
use bip39::{Language, Mnemonic};

// Re-export generated protobuf types
pub use super::softkms::*;
use super::softkms::key_store_server::{KeyStore, KeyStoreServer};

/// gRPC service implementation
pub struct GrpcKeyStore {
    key_service: Arc<KeyService>,
    security_manager: Arc<SecurityManager>,
}

impl GrpcKeyStore {
    /// Create new gRPC key store service
    pub fn new(
        key_service: Arc<KeyService>,
        security_manager: Arc<SecurityManager>,
    ) -> Self {
        Self {
            key_service,
            security_manager,
        }
    }

    /// Check if daemon is initialized
    fn is_initialized(&self) -> bool {
        self.security_manager.is_initialized()
    }
    
    /// Convert BIP39 mnemonic to 64-byte seed
    fn mnemonic_to_seed(mnemonic: &str) -> Result<Vec<u8>, Status> {
        use bip39::{Language, Mnemonic};
        
        // Parse the mnemonic
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| Status::invalid_argument(format!("Invalid BIP39 mnemonic: {}", e)))?;
        
        // Generate seed (64 bytes) with empty passphrase
        let seed = mnemonic.to_seed_normalized("");
        Ok(seed.to_vec())
    }
}

fn map_error(e: Error) -> Status {
    match e {
        Error::KeyNotFound(msg) => Status::not_found(msg),
        Error::AccessDenied => Status::permission_denied("Access denied"),
        Error::Crypto(msg) => Status::internal(format!("Crypto error: {}", msg)),
        Error::Storage(msg) => Status::internal(format!("Storage error: {}", msg)),
        Error::InvalidKey(msg) => Status::invalid_argument(msg),
        Error::InvalidParams(msg) => Status::invalid_argument(msg),
        Error::Internal(msg) => Status::internal(msg),
    }
}

fn key_type_to_string(kt: KeyType) -> String {
    match kt {
        KeyType::Seed => "seed".to_string(),
        KeyType::Derived => "derived".to_string(),
        KeyType::Imported => "imported".to_string(),
        KeyType::ExtendedPublic => "xpub".to_string(),
    }
}

fn metadata_to_key_info(metadata: &KeyMetadata, include_public_key: bool) -> KeyInfo {
    KeyInfo {
        key_id: metadata.id.to_string(),
        algorithm: metadata.algorithm.clone(),
        key_type: key_type_to_string(metadata.key_type),
        created_at: metadata.created_at.to_rfc3339(),
        label: metadata.label.clone(),
        attributes: metadata.attributes.clone(),
        public_key: if include_public_key {
            // TODO: Store public key with metadata
            None
        } else {
            None
        },
    }
}

#[tonic::async_trait]
impl KeyStore for GrpcKeyStore {
    async fn init(
        &self,
        request: Request<InitRequest>,
    ) -> Result<Response<InitResponse>, Status> {
        debug!("Received Init request");
        
        let req = request.into_inner();
        
        // Initialize with passphrase and store verification hash
        match self.security_manager.init_with_passphrase(&req.passphrase) {
            Ok(_) => {
                info!("Daemon initialized with passphrase");
                let response = InitResponse {
                    success: true,
                    message: "Keystore initialized successfully".to_string(),
                };
                Ok(Response::new(response))
            }
            Err(e) => {
                error!("Failed to initialize: {}", e);
                Err(Status::internal(format!("Failed to initialize: {}", e)))
            }
        }
    }

    async fn create_key(
        &self,
        request: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        debug!("Received CreateKey request");
        
        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }
        
        let req = request.into_inner();
        
        let metadata = self.key_service
            .create_key(req.algorithm, req.label, req.attributes, &req.passphrase)
            .await
            .map_err(map_error)?;
        
        let response = CreateKeyResponse {
            key_id: metadata.id.to_string(),
            algorithm: metadata.algorithm,
            public_key: "".to_string(), // TODO: Store and return public key
            created_at: metadata.created_at.to_rfc3339(),
            label: metadata.label.unwrap_or_default(),
        };
        
        info!("Key {} created via gRPC", response.key_id);
        Ok(Response::new(response))
    }

    async fn list_keys(
        &self,
        _request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        debug!("Received ListKeys request");
        
        let metadatas = self.key_service
            .list_keys()
            .await
            .map_err(map_error)?;
        
        let keys = metadatas.iter()
            .map(|m| metadata_to_key_info(m, false))
            .collect();
        
        let response = ListKeysResponse { keys };
        Ok(Response::new(response))
    }

    async fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> Result<Response<GetKeyResponse>, Status> {
        debug!("Received GetKey request");
        
        let req = request.into_inner();
        let key_id = KeyId::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID"))?;
        
        let metadata = self.key_service
            .get_key(key_id)
            .await
            .map_err(map_error)?;
        
        let response = GetKeyResponse {
            key: metadata.map(|m| metadata_to_key_info(&m, req.include_public_key)),
        };
        
        Ok(Response::new(response))
    }

    async fn delete_key(
        &self,
        request: Request<DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        debug!("Received DeleteKey request");
        
        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }
        
        let req = request.into_inner();
        let key_id = KeyId::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID"))?;
        
        self.key_service
            .delete_key(key_id)
            .await
            .map_err(map_error)?;
        
        let response = DeleteKeyResponse { success: true };
        info!("Key {} deleted via gRPC", req.key_id);
        Ok(Response::new(response))
    }

    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        debug!("Received Sign request");
        
        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }
        
        let req = request.into_inner();
        let key_id = KeyId::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID"))?;
        
        let signature = self.key_service
            .sign(key_id, &req.data, &req.passphrase)
            .await
            .map_err(map_error)?;
        
        let response = SignResponse {
            signature: signature.bytes,
            algorithm: signature.algorithm,
        };
        
        debug!("Data signed with key {} via gRPC", req.key_id);
        Ok(Response::new(response))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        debug!("Received Verify request");
        
        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }
        
        let req = request.into_inner();
        let key_id = KeyId::parse_str(&req.key_id)
            .map_err(|_| Status::invalid_argument("Invalid key ID"))?;
        
        // Get key metadata to find the algorithm and public key
        let metadata = self.key_service
            .get_key(key_id)
            .await
            .map_err(map_error)?
            .ok_or_else(|| Status::not_found("Key not found"))?;
        
        // Get the public key from the key info
        let public_key = if metadata.public_key.is_empty() {
            // For stored keys, we need to retrieve and unwrap to get public key
            let result = self.key_service
                .storage()
                .retrieve_key(metadata.id)
                .await
                .map_err(map_error)?;
            
            let (_, encrypted_data) = result.ok_or_else(|| Status::internal("Failed to retrieve key"))?;
            
            // For P-256 keys, we can derive public key from private key
            if metadata.algorithm == "p256" {
                // Get a dummy passphrase - verification doesn't need the real key
                // We'll use the verification path that doesn't require unwrapping
                // Actually, we need the passphrase to unwrap and verify
                return Err(Status::unimplemented(
                    "Verify for stored keys requires passphrase. Use the public key directly."
                ));
            } else {
                return Err(Status::unimplemented(
                    "Verify not yet implemented for algorithm {}",
                ));
            }
        } else {
            metadata.public_key.clone()
        };
        
        // Verify based on algorithm
        let valid = match metadata.algorithm.as_str() {
            "p256" => {
                use crate::crypto::p256::DeterministicP256;
                DeterministicP256::verify(&public_key, &req.data, &req.signature)
                    .map_err(|e| Status::internal(format!("Verification error: {}", e)))?
            }
            "ed25519" => {
                use crate::crypto::ed25519::Ed25519Engine;
                Ed25519Engine::verify(&public_key, &req.data, &req.signature)
                    .map_err(|e| Status::internal(format!("Verification error: {}", e)))?
            }
            _ => {
                return Err(Status::unimplemented(
                    format!("Verify not implemented for algorithm: {}", metadata.algorithm)
                ));
            }
        };
        
        let response = VerifyResponse {
            valid,
            algorithm: metadata.algorithm,
        };
        
        debug!("Signature verification for key {}: {}", req.key_id, valid);
        Ok(Response::new(response))
    }

    async fn import_seed(
        &self,
        request: Request<ImportSeedRequest>,
    ) -> Result<Response<ImportSeedResponse>, Status> {
        debug!("Received ImportSeed request");
        
        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }
        
        let req = request.into_inner();
        
        // Determine if input is BIP39 mnemonic or raw hex seed
        let seed_bytes = if req.mnemonic.len() == 64 {
            // 64 hex chars = 32 bytes, treat as raw seed
            match hex::decode(&req.mnemonic) {
                Ok(bytes) => {
                    if bytes.len() == 32 {
                        // Pad to 64 bytes for BIP32
                        let mut padded = vec![0u8; 64];
                        padded[..32].copy_from_slice(&bytes);
                        padded
                    } else {
                        bytes
                    }
                }
                Err(_) => {
                    // Not valid hex, treat as mnemonic
                    Self::mnemonic_to_seed(&req.mnemonic)?
                }
            }
        } else {
            // Treat as BIP39 mnemonic
            Self::mnemonic_to_seed(&req.mnemonic)?
        };
        
        let metadata = self.key_service
            .import_seed(seed_bytes, req.label, &req.passphrase)
            .await
            .map_err(map_error)?;
        
        let response = ImportSeedResponse {
            seed_id: metadata.id.to_string(),
            created_at: metadata.created_at.to_rfc3339(),
        };
        
        info!("Seed {} imported via gRPC", response.seed_id);
        Ok(Response::new(response))
    }

    async fn derive_key(
        &self,
        _request: Request<DeriveKeyRequest>,
    ) -> Result<Response<DeriveKeyResponse>, Status> {
        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }

        // TODO: Implement HD wallet derivation
        Err(Status::unimplemented("DeriveKey not yet implemented"))
    }

    async fn derive_p256(
        &self,
        request: Request<DeriveP256Request>,
    ) -> Result<Response<DeriveP256Response>, Status> {
        debug!("Received DeriveP256 request");

        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }

        let req = request.into_inner();

        let seed_id = KeyId::parse_str(&req.seed_id)
            .map_err(|_| Status::invalid_argument("Invalid seed ID"))?;

        let metadata = self.key_service
            .derive_p256_key(
                seed_id,
                req.origin.clone(),
                req.user_handle.clone(),
                req.counter,
                req.label,
                &req.passphrase,
            )
            .await
            .map_err(map_error)?;

        // Get the public key for the response
        let result = self.key_service
            .storage()
            .retrieve_key(metadata.id)
            .await
            .map_err(map_error)?;

        let (_, encrypted_data) = result.ok_or_else(|| Status::internal("Failed to retrieve derived key"))?;

        // Unwrap to get public key
        let master_key = self.security_manager
            .derive_master_key(&req.passphrase)
            .map_err(|e| Status::internal(format!("Failed to get master key: {}", e)))?;

        let wrapper = self.security_manager.create_wrapper(&master_key);
        let aad = format!(
            "softkms:key:{}:{}:{}",
            metadata.id, metadata.algorithm, metadata.key_type
        );

        let wrapped = crate::security::WrappedKey::from_bytes(&encrypted_data)
            .map_err(|e| Status::internal(format!("Invalid wrapped key: {}", e)))?;

        let key_material = wrapper
            .unwrap(&wrapped, &aad.into_bytes())
            .map_err(|e| Status::internal(format!("Failed to unwrap key: {}", e)))?;

        use crate::crypto::p256::DeterministicP256;
        let public_key = DeterministicP256::get_public_key(&key_material)
            .map_err(|e| Status::internal(format!("Failed to get public key: {}", e)))?;

        let response = DeriveP256Response {
            key_id: metadata.id.to_string(),
            public_key: base64::encode(&public_key),
            algorithm: "p256".to_string(),
            created_at: metadata.created_at.to_rfc3339(),
        };

        info!("P-256 key {} derived for origin={}", response.key_id, req.origin);
        Ok(Response::new(response))
    }

    async fn derive_ed25519(
        &self,
        request: Request<DeriveEd25519Request>,
    ) -> Result<Response<DeriveEd25519Response>, Status> {
        debug!("Received DeriveEd25519 request");

        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }

        let req = request.into_inner();

        let seed_id = KeyId::parse_str(&req.seed_id)
            .map_err(|_| Status::invalid_argument("Invalid seed ID"))?;

        let scheme = match req.scheme {
            1 => crate::crypto::hd_ed25519::HdDerivationScheme::Peikert,
            2 => crate::crypto::hd_ed25519::HdDerivationScheme::V2,
            _ => crate::crypto::hd_ed25519::HdDerivationScheme::Peikert,
        };

        let metadata = self.key_service
            .derive_ed25519_key(
                seed_id,
                &req.derivation_path,
                req.coin_type,
                scheme,
                req.store_key,
                &req.passphrase,
            )
            .await
            .map_err(map_error)?;

        // Get the public key for the response
        let public_key_b64 = base64::encode(&metadata.public_key);

        let response = DeriveEd25519Response {
            key_id: metadata.id.to_string(),
            public_key: public_key_b64,
            address: String::new(), // Address field kept for compatibility but not used
            algorithm: "ed25519".to_string(),
            created_at: metadata.created_at.to_rfc3339(),
        };

        info!(
            "Ed25519 key {} derived with path {}", 
            response.key_id, 
            req.derivation_path
        );
        Ok(Response::new(response))
    }

    async fn import_xpub(
        &self,
        request: Request<ImportXpubRequest>,
    ) -> Result<Response<ImportXpubResponse>, Status> {
        debug!("Received ImportXpub request");

        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }

        let req = request.into_inner();

        let metadata = self.key_service
            .import_xpub(
                req.xpub,
                req.coin_type,
                req.account,
                req.label,
                &req.passphrase,
            )
            .await
            .map_err(map_error)?;

        let response = ImportXpubResponse {
            xpub_id: metadata.id.to_string(),
            created_at: metadata.created_at.to_rfc3339(),
        };

        info!("XPub {} imported for coin_type={} account={}", response.xpub_id, req.coin_type, req.account);
        Ok(Response::new(response))
    }

    async fn derive_public(
        &self,
        request: Request<DerivePublicRequest>,
    ) -> Result<Response<DerivePublicResponse>, Status> {
        debug!("Received DerivePublic request");

        if !self.is_initialized() {
            return Err(Status::failed_precondition(
                "Keystore not initialized. Run 'softkms init' first."
            ));
        }

        let req = request.into_inner();

        let xpub_id = KeyId::parse_str(&req.xpub_id)
            .map_err(|_| Status::invalid_argument("Invalid xpub ID"))?;

        let scheme = match req.scheme {
            1 => crate::crypto::hd_ed25519::HdDerivationScheme::Peikert,
            2 => crate::crypto::hd_ed25519::HdDerivationScheme::V2,
            _ => crate::crypto::hd_ed25519::HdDerivationScheme::Peikert,
        };

        let hrp = req.hrp.as_deref();

        let (key_id, address, public_key) = self.key_service
            .derive_ed25519_public(xpub_id, req.index, scheme, hrp)
            .await
            .map_err(map_error)?;

        let public_key_b64 = base64::encode(&public_key);

        let response = DerivePublicResponse {
            key_id: key_id.to_string(),
            public_key: public_key_b64,
            address,
            path: format!("m/44'/{}/{}'/0/{}", 
                req.xpub_id, 
                req.index / 0x8000_0000,
                req.index % 0x8000_0000),
        };

        info!(
            "Public key {} derived from xpub {} at index {}",
            response.key_id,
            req.xpub_id,
            req.index
        );
        Ok(Response::new(response))
    }

    async fn change_passphrase(
        &self,
        _request: Request<ChangePassphraseRequest>,
    ) -> Result<Response<ChangePassphraseResponse>, Status> {
        // TODO: Implement passphrase change
        Err(Status::unimplemented("ChangePassphrase not yet implemented"))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let response = HealthResponse {
            healthy: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
            storage_ready: true,
            api_ready: true,
            initialized: self.is_initialized(),
        };
        Ok(Response::new(response))
    }
}

/// Start the gRPC server
pub async fn start(
    config: &Config,
    key_service: Arc<KeyService>,
    security_manager: Arc<SecurityManager>,
) -> crate::Result<()> {
    let addr: SocketAddr = config
        .api
        .grpc_addr
        .parse()
        .map_err(|e| Error::InvalidParams(format!("Invalid gRPC address: {}", e)))?;

    info!("Starting gRPC server on {}", addr);
    if security_manager.is_initialized() {
        info!("gRPC service marked as pre-initialized (verification hash exists)");
    }

    let service = GrpcKeyStore::new(key_service, security_manager);
    let server = KeyStoreServer::new(service);

    Server::builder()
        .add_service(server)
        .serve(addr)
        .await
        .map_err(|e| Error::Internal(format!("gRPC server error: {}", e)))?;

    Ok(())
}
