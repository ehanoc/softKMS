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

// Re-export generated protobuf types
pub use super::softkms::*;
use super::softkms::key_store_server::{KeyStore, KeyStoreServer};

/// gRPC service implementation
pub struct GrpcKeyStore {
    key_service: Arc<KeyService>,
    security_manager: Arc<SecurityManager>,
    initialized: Arc<std::sync::atomic::AtomicBool>,
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
            initialized: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Check if daemon is initialized
    fn is_initialized(&self) -> bool {
        self.initialized.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Mark as initialized
    fn set_initialized(&self) {
        self.initialized.store(true, std::sync::atomic::Ordering::SeqCst);
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
        
        // Derive master key from passphrase
        match self.security_manager.derive_master_key(&req.passphrase) {
            Ok(_) => {
                self.set_initialized();
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

    async fn import_seed(
        &self,
        request: Request<ImportSeedRequest>,
    ) -> Result<Response<ImportSeedResponse>, Status> {
        debug!("Received ImportSeed request");
        
        let req = request.into_inner();
        
        // Parse mnemonic or use raw seed
        // For now, treat as raw seed bytes
        let seed = req.mnemonic.as_bytes().to_vec();
        
        let metadata = self.key_service
            .import_seed(seed, req.label, &req.passphrase)
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
        // TODO: Implement HD wallet derivation
        Err(Status::unimplemented("DeriveKey not yet implemented"))
    }

    async fn derive_p256(
        &self,
        request: Request<DeriveP256Request>,
    ) -> Result<Response<DeriveP256Response>, Status> {
        debug!("Received DeriveP256 request");

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
            .storage
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

    let service = GrpcKeyStore::new(key_service, security_manager);
    let server = KeyStoreServer::new(service);

    Server::builder()
        .add_service(server)
        .serve(addr)
        .await
        .map_err(|e| Error::Internal(format!("gRPC server error: {}", e)))?;

    Ok(())
}
