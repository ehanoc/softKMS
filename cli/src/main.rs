//! softKMS CLI - Command line interface for softKMS
//!
//! This CLI communicates with the softKMS daemon via gRPC.
//! All key operations are performed by the daemon - keys NEVER
//! leave the daemon process. The CLI only sends requests and
//! receives metadata/signatures.
//!
//! Security Model:
//! - Daemon prompts for passphrase ONCE during initialization
//! - Passphrase is cached in daemon memory
//! - No passphrase prompts needed for normal operations

use clap::{Parser, Subcommand};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rpassword::prompt_password;

use softkms::api::softkms::key_store_client::KeyStoreClient;
use softkms::api::softkms::{
    CreateKeyRequest, DeleteKeyRequest, GetKeyRequest,
    ImportSeedRequest, ListKeysRequest, SignRequest,
    DeriveP256Request, HealthRequest,
};

#[derive(Parser)]
#[command(name = "softkms")]
#[command(about = "SoftKMS - Modern Software Key Management System")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Server address
    #[arg(short, long, default_value = "http://127.0.0.1:50051")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key
    Generate {
        /// Algorithm (ed25519, p256, ecdsa, rsa)
        #[arg(short, long)]
        algorithm: String,
        
        /// Key label
        #[arg(short, long)]
        label: Option<String>,
        
        /// Derive from seed (for deterministic keys)
        #[arg(long)]
        from_seed: Option<String>,
        
        /// Origin/domain for derivation (e.g., "github.com")
        #[arg(long)]
        origin: Option<String>,
        
        /// User handle for derivation
        #[arg(long)]
        user_handle: Option<String>,
        
        /// Counter for multiple keys per origin
        #[arg(long, default_value = "0")]
        counter: u32,
    },
    
    /// List all keys
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
    
    /// Sign data with a key
    Sign {
        /// Key ID (alternative to --label)
        #[arg(short, long, group = "key_ref")]
        key: Option<String>,
        
        /// Key label (alternative to --key)
        #[arg(short, long, group = "key_ref")]
        label: Option<String>,
        
        /// Data to sign (raw bytes, will be base64 encoded for transport)
        #[arg(short, long)]
        data: String,
    },
    
    /// Import a seed
    ImportSeed {
        /// Seed mnemonic or raw hex seed
        #[arg(short, long)]
        mnemonic: String,
        
        /// Label for the seed
        #[arg(short, long)]
        label: Option<String>,
    },
    
    /// Derive a key from seed (BIP32)
    Derive {
        /// Seed ID
        #[arg(short, long)]
        seed: String,
        
        /// Derivation path (e.g., m/44'/283'/0'/0/0)
        #[arg(short, long)]
        path: String,
        
        /// Label for derived key
        #[arg(short, long)]
        label: Option<String>,
    },
    
    
    /// Delete a key
    Delete {
        /// Key ID (alternative to --label)
        #[arg(short, long, group = "delete_key_ref")]
        key: Option<String>,
        
        /// Key label (alternative to --key)
        #[arg(short, long, group = "delete_key_ref")]
        label: Option<String>,
        
        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },
    
    /// Show key information
    Info {
        /// Key ID (alternative to --label)
        #[arg(short, long, group = "info_key_ref")]
        key: Option<String>,
        
        /// Key label (alternative to --key)
        #[arg(short, long, group = "info_key_ref")]
        label: Option<String>,
    },
    
    /// Health check
    Health,
}

/// Lookup key ID by label
async fn lookup_key_by_label(
    client: &mut KeyStoreClient<tonic::transport::Channel>,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let list_request = tonic::Request::new(ListKeysRequest {
        include_public_keys: false,
    });
    
    let response = client.list_keys(list_request).await?;
    let list: softkms::api::softkms::ListKeysResponse = response.into_inner();
    
    let matching_keys: Vec<_> = list.keys.iter()
        .filter(|k| k.label.as_deref() == Some(label))
        .collect();
    
    match matching_keys.len() {
        0 => {
            Err(format!("No key found with label '{}'", label).into())
        }
        1 => Ok(matching_keys[0].key_id.clone()),
        _ => {
            eprintln!("Multiple keys found with label '{}':", label);
            for k in matching_keys {
                println!("  {} (created: {})", k.key_id, k.created_at);
            }
            Err("Ambiguous label - use --key with the UUID".into())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Connect to the daemon
    let mut client = KeyStoreClient::connect(cli.server.clone()).await?;
    
    match cli.command {
        Commands::Generate { algorithm, label, from_seed, origin, user_handle, counter } => {
            // Check if this is a derivation request
            if let Some(seed_id) = from_seed {
                // Derive from seed (P-256 deterministic)
                if algorithm != "p256" {
                    eprintln!("--from-seed only supported with --algorithm p256");
                    std::process::exit(1);
                }
                
                let origin = match origin {
                    Some(o) => o,
                    None => {
                        eprintln!("--origin required when using --from-seed");
                        std::process::exit(1);
                    }
                };
                
                let user_handle = match user_handle {
                    Some(uh) => uh,
                    None => {
                        eprintln!("--user-handle required when using --from-seed");
                        std::process::exit(1);
                    }
                };
                
                // Prompt for passphrase
                let passphrase = prompt_password("Enter passphrase: ")?;
                if passphrase.is_empty() {
                    eprintln!("Passphrase cannot be empty");
                    std::process::exit(1);
                }
                
                let request = tonic::Request::new(DeriveP256Request {
                    seed_id: seed_id.clone(),
                    origin: origin.clone(),
                    user_handle: user_handle.clone(),
                    counter,
                    label,
                    passphrase,
                });
                
                match client.derive_p256(request).await {
                    Ok(response) => {
                        let resp = response.into_inner();
                        println!("P-256 key derived successfully:");
                        println!("  Key ID: {}", resp.key_id);
                        println!("  Algorithm: {}", resp.algorithm);
                        println!("  Origin: {}", origin);
                        println!("  User Handle: {}", user_handle);
                        println!("  Counter: {}", counter);
                        println!("  Public Key (base64): {}...", &resp.public_key[..50.min(resp.public_key.len())]);
                        println!("  Created: {}", resp.created_at);
                    }
                    Err(e) => {
                        eprintln!("Failed to derive P-256 key: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // Regular key generation
                // Prompt for passphrase
                let passphrase = prompt_password("Enter passphrase: ")?;
                if passphrase.is_empty() {
                    eprintln!("Passphrase cannot be empty");
                    std::process::exit(1);
                }

                let request = tonic::Request::new(CreateKeyRequest {
                    algorithm: algorithm.clone(),
                    label,
                    attributes: std::collections::HashMap::new(),
                    passphrase,
                });

                match client.create_key(request).await {
                    Ok(response) => {
                        let key = response.into_inner();
                        println!("Key generated successfully:");
                        println!("  ID: {}", key.key_id);
                        println!("  Algorithm: {}", key.algorithm);
                        if !key.label.is_empty() {
                            println!("  Label: {}", key.label);
                        }
                        println!("  Created: {}", key.created_at);
                    }
                    Err(e) => {
                        eprintln!("Failed to generate key: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        
        Commands::List { detailed: _ } => {
            let request = tonic::Request::new(ListKeysRequest {
                include_public_keys: false,
            });
            
            match client.list_keys(request).await {
                Ok(response) => {
                    let list: softkms::api::softkms::ListKeysResponse = response.into_inner();
                    if list.keys.is_empty() {
                        println!("No keys found.");
                    } else {
                        println!("Keys:");
                        for key in &list.keys {
                            println!("  {}:", key.key_id);
                            println!("    Algorithm: {}", key.algorithm);
                            println!("    Type: {}", key.key_type);
                            if let Some(ref label) = key.label {
                                println!("    Label: {}", label);
                            }
                            println!("    Created: {}", key.created_at);
                        }
                        println!("\nTotal: {} keys", list.keys.len());
                    }
                }
                Err(e) => {
                    eprintln!("Failed to list keys: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Sign { key, label, data } => {
            // Determine key_id from key or label
            let key_id = if let Some(kid) = key {
                kid
            } else if let Some(lbl) = label {
                // Lookup key by label
                let list_request = tonic::Request::new(ListKeysRequest {
                    include_public_keys: false,
                });
                
                match client.list_keys(list_request).await {
                    Ok(response) => {
                        let list: softkms::api::softkms::ListKeysResponse = response.into_inner();
                        let matching_keys: Vec<_> = list.keys.iter()
                            .filter(|k| k.label.as_deref() == Some(&lbl))
                            .collect();
                        
                        match matching_keys.len() {
                            0 => {
                                eprintln!("No key found with label '{}'", lbl);
                                std::process::exit(1);
                            }
                            1 => matching_keys[0].key_id.clone(),
                            _ => {
                                eprintln!("Multiple keys found with label '{}'. Please use --key with the UUID:", lbl);
                                for k in matching_keys {
                                    println!("  {} (created: {})", k.key_id, k.created_at);
                                }
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to lookup key by label: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Either --key or --label must be specified");
                std::process::exit(1);
            };
            
            // Prompt for passphrase
            let passphrase = prompt_password("Enter passphrase: ")?;
            if passphrase.is_empty() {
                eprintln!("Passphrase cannot be empty");
                std::process::exit(1);
            }
            
            // Decode base64 data if provided as base64, otherwise treat as raw string
            let data_bytes = if let Ok(decoded) = BASE64.decode(&data) {
                decoded
            } else {
                data.as_bytes().to_vec()
            };
            
            let request = tonic::Request::new(SignRequest {
                key_id: key_id.clone(),
                data: data_bytes,
                passphrase,
            });
            
            match client.sign(request).await {
                Ok(response) => {
                    let sig: softkms::api::softkms::SignResponse = response.into_inner();
                    println!("Signature (base64): {}", BASE64.encode(&sig.signature));
                    println!("Algorithm: {}", sig.algorithm);
                }
                Err(e) => {
                    eprintln!("Failed to sign data: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::ImportSeed { mnemonic, label } => {
            // Prompt for passphrase
            let passphrase = prompt_password("Enter passphrase: ")?;
            if passphrase.is_empty() {
                eprintln!("Passphrase cannot be empty");
                std::process::exit(1);
            }

            let request = tonic::Request::new(ImportSeedRequest {
                mnemonic,
                label,
                passphrase,
            });
            
            match client.import_seed(request).await {
                Ok(response) => {
                    let seed: softkms::api::softkms::ImportSeedResponse = response.into_inner();
                    println!("Seed imported successfully:");
                    println!("  ID: {}", seed.seed_id);
                    println!("  Created: {}", seed.created_at);
                }
                Err(e) => {
                    eprintln!("Failed to import seed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Derive { seed: _, path: _, label: _ } => {
            println!("HD wallet key derivation not yet implemented.");
            std::process::exit(1);
        }
        
        
        Commands::Delete { key, label, force } => {
            // Determine key_id from key or label
            let key_id = if let Some(kid) = key {
                kid
            } else if let Some(lbl) = &label {
                match lookup_key_by_label(&mut client, lbl).await {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Either --key or --label must be specified");
                std::process::exit(1);
            };
            
            if !force {
                println!("Are you sure you want to delete key {}?", key_id);
                println!("This operation cannot be undone.");
                println!("Use --force to confirm deletion.");
                return Ok(());
            }
            
            let request = tonic::Request::new(DeleteKeyRequest {
                key_id: key_id.clone(),
                force: true,
            });
            
            match client.delete_key(request).await {
                Ok(_) => {
                    println!("Key {} deleted successfully.", key_id);
                }
                Err(e) => {
                    eprintln!("Failed to delete key: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Info { key, label } => {
            // Determine key_id from key or label
            let key_id = if let Some(kid) = key {
                kid
            } else if let Some(lbl) = &label {
                match lookup_key_by_label(&mut client, lbl).await {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Either --key or --label must be specified");
                std::process::exit(1);
            };
            
            let request = tonic::Request::new(GetKeyRequest {
                key_id: key_id.clone(),
                include_public_key: true,
            });
            
            match client.get_key(request).await {
                Ok(response) => {
                    let info: softkms::api::softkms::GetKeyResponse = response.into_inner();
                    if let Some(key_info) = info.key {
                        println!("Key Information:");
                        println!("  ID: {}", key_info.key_id);
                        println!("  Algorithm: {}", key_info.algorithm);
                        println!("  Type: {}", key_info.key_type);
                        if let Some(ref label) = key_info.label {
                            println!("  Label: {}", label);
                        }
                        println!("  Created: {}", key_info.created_at);
                        println!("  Attributes: {:?}", key_info.attributes);
                        if let Some(ref pk) = key_info.public_key {
                            let len: usize = pk.len();
                            println!("  Public Key: {}...", &pk[..50.min(len)]);
                        }
                    } else {
                        println!("Key {} not found.", key_id);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to get key info: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Health => {
            let request = tonic::Request::new(HealthRequest {});
            
            match client.health(request).await {
                Ok(response) => {
                    let health: softkms::api::softkms::HealthResponse = response.into_inner();
                    if health.healthy {
                        println!("Daemon is healthy");
                        println!("  Version: {}", health.version);
                        println!("  Storage: {}", if health.storage_ready { "ready" } else { "not ready" });
                        println!("  API: {}", if health.api_ready { "ready" } else { "not ready" });
                        println!("  Initialized: {}", if health.initialized { "yes" } else { "no - run 'init' first" });
                    } else {
                        println!("Daemon is not healthy");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check health: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
    
    Ok(())
}
