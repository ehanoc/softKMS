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
    DeriveP256Request, DeriveEd25519Request, HealthRequest, InitRequest,
    VerifyRequest, DerivationScheme,
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
    
    /// Passphrase for keystore (if not provided, will prompt interactively)
    #[arg(short = 'p', long)]
    passphrase: Option<String>,
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

        /// Data encoding: raw (default) or hex
        #[arg(long, default_value = "raw")]
        encoding: String,
    },

    /// Verify a signature
    Verify {
        /// Key ID (alternative to --label)
        #[arg(short, long, group = "verify_key_ref")]
        key: Option<String>,

        /// Key label (alternative to --key)
        #[arg(short, long, group = "verify_key_ref")]
        label: Option<String>,

        /// Data that was signed (raw bytes or base64)
        #[arg(short, long)]
        data: String,

        /// Signature to verify (base64 encoded)
        #[arg(short, long)]
        signature: String,
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
        /// Algorithm to derive (ed25519, p256)
        #[arg(short, long, default_value = "ed25519")]
        algorithm: String,
        
        /// Seed ID
        #[arg(short, long)]
        seed: String,

        /// Derivation path (e.g., m/44'/283'/0'/0/0)
        #[arg(short, long)]
        path: String,

        /// Derivation scheme: peikert (default) or v2
        #[arg(long, default_value = "peikert")]
        scheme: String,

        /// Origin for P-256 derivation
        #[arg(long)]
        origin: Option<String>,

        /// User handle for P-256 derivation
        #[arg(long)]
        user_handle: Option<String>,

        /// Counter for P-256 derivation
        #[arg(long, default_value = "0")]
        counter: u32,

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
    
    /// Initialize the keystore with a passphrase
    Init {
        /// Require passphrase confirmation
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        confirm: bool,
    },

    /// PKCS#11 provider information
    Pkcs11 {
        /// Show PKCS#11 module path
        #[arg(long)]
        module: bool,
    },
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

/// Get passphrase from CLI arg or prompt interactively
fn get_passphrase(cli_pass: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(pass) = cli_pass {
        if pass.is_empty() {
            return Err("Passphrase cannot be empty".into());
        }
        Ok(pass)
    } else {
        let passphrase = prompt_password("Enter passphrase: ")?;
        if passphrase.is_empty() {
            return Err("Passphrase cannot be empty".into());
        }
        Ok(passphrase)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Handle PKCS#11 command - doesn't need daemon connection
    if let Commands::Pkcs11 { module } = cli.command {
        if module {
            let path = softkms::pkcs11::get_module_path();
            println!("PKCS#11 Module Path:");
            println!("  {}", path);
            println!("");
            println!("To use with applications:");
            println!("  export PKCS11_MODULE={}", path);
        } else {
            let info = softkms::pkcs11::get_info();
            println!("PKCS#11 Provider Information:");
            println!("  Name: {}", info.name);
            println!("  Version: {}.{}", info.version.0, info.version.1);
            println!("  Description: {}", info.description);
            println!("");
            println!("Use --module to show the module path");
        }
        return Ok(());
    }
    
    let mut client = KeyStoreClient::connect(cli.server.clone()).await?;
    
    match cli.command {
        Commands::Generate { algorithm, label, from_seed, origin, user_handle, counter } => {
            if let Some(seed_id) = from_seed {
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

                let passphrase = match get_passphrase(cli.passphrase.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                };
                
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
                let passphrase = match get_passphrase(cli.passphrase.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                };

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
        
        Commands::Sign { key, label, data, encoding: _ } => {
            let key_id = if let Some(kid) = key {
                kid
            } else if let Some(lbl) = label {
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
            
            let passphrase = match get_passphrase(cli.passphrase.clone()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };

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

        Commands::Verify { key, label, data, signature } => {
            let key_id = if let Some(kid) = key {
                kid
            } else if let Some(lbl) = label {
                match lookup_key_by_label(&mut client, &lbl).await {
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

            let data_bytes = if let Ok(decoded) = BASE64.decode(&data) {
                decoded
            } else {
                data.as_bytes().to_vec()
            };

            let signature_bytes = match BASE64.decode(&signature) {
                Ok(decoded) => decoded,
                Err(e) => {
                    eprintln!("Failed to decode signature from base64: {}", e);
                    std::process::exit(1);
                }
            };

            let request = tonic::Request::new(VerifyRequest {
                key_id: key_id.clone(),
                data: data_bytes,
                signature: signature_bytes,
            });

            match client.verify(request).await {
                Ok(response) => {
                    let result: softkms::api::softkms::VerifyResponse = response.into_inner();
                    if result.valid {
                        println!("Signature is VALID");
                        println!("Algorithm: {}", result.algorithm);
                    } else {
                        println!("Signature is INVALID");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to verify signature: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::ImportSeed { mnemonic, label } => {
            let passphrase = match get_passphrase(cli.passphrase.clone()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };

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
        
        Commands::Derive { algorithm, seed, path, scheme, origin, user_handle, counter, label } => {
            let passphrase = match get_passphrase(cli.passphrase.clone()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };

            // First, try to resolve seed as ID, then as label
            let seed_id = if seed.len() == 36 && seed.chars().nth(8) == Some('-') && seed.chars().nth(13) == Some('-') && seed.chars().nth(18) == Some('-') && seed.chars().nth(23) == Some('-') {
                // Looks like a UUID format
                seed.clone()
            } else {
                // Try to resolve as label
                match lookup_key_by_label(&mut client, &seed).await {
                    Ok(id) => {
                        println!("Resolved seed label '{}' to ID: {}", seed, id);
                        id
                    }
                    Err(e) => {
                        eprintln!("Failed to find seed by label '{}': {}", seed, e);
                        std::process::exit(1);
                    }
                }
            };

            // Extract coin type from path (m/44'/coin_type'/...)
            let coin_type: u32 = path.split('/').nth(2)
                .and_then(|s| s.trim_end_matches('\'').parse().ok())
                .unwrap_or(283); // Default to Algorand (283) if not found

            match algorithm.as_str() {
                "ed25519" => {
                    // Map scheme string to enum
                    let scheme_enum = match scheme.as_str() {
                        "v2" => DerivationScheme::V2 as i32,
                        _ => DerivationScheme::Peikert as i32,
                    };

                    let request = tonic::Request::new(DeriveEd25519Request {
                        seed_id,
                        derivation_path: path,
                        coin_type,
                        scheme: scheme_enum,
                        store_key: true,
                        label,
                        passphrase,
                    });
                    
                    match client.derive_ed25519(request).await {
                        Ok(response) => {
                            let result = response.into_inner();
                            println!("Ed25519 key derived successfully:");
                            println!("  Key ID: {}", result.key_id);
                            println!("  Algorithm: {}", result.algorithm);
                            println!("  Public Key (base64): {}", result.public_key);
                            if !result.address.is_empty() {
                                println!("  Address: {}", result.address);
                            }
                            println!("  Created: {}", result.created_at);
                        }
                        Err(e) => {
                            eprintln!("Failed to derive Ed25519 key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "p256" => {
                    // P256 derivation
                    let origin = origin.expect("--origin required for p256 derivation");
                    let user_handle = user_handle.expect("--user-handle required for p256 derivation");
                    
                    let request = tonic::Request::new(DeriveP256Request {
                        seed_id,
                        origin,
                        user_handle,
                        counter,
                        label,
                        passphrase,
                    });
                    
                    match client.derive_p256(request).await {
                        Ok(response) => {
                            let result = response.into_inner();
                            println!("P-256 key derived successfully:");
                            println!("  Key ID: {}", result.key_id);
                            println!("  Algorithm: {}", result.algorithm);
                            println!("  Public Key (base64): {}", result.public_key);
                            println!("  Created: {}", result.created_at);
                        }
                        Err(e) => {
                            eprintln!("Failed to derive P-256 key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    eprintln!("Unknown algorithm: {}. Use 'ed25519' or 'p256'", algorithm);
                    std::process::exit(1);
                }
            }
        }
        
        
        Commands::Delete { key, label, force } => {
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
        
        Commands::Init { confirm } => {
            let passphrase = match get_passphrase(cli.passphrase.clone()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };

            if confirm {
                let confirm_pass = rpassword::prompt_password("Confirm passphrase: ")?;
                if passphrase != confirm_pass {
                    eprintln!("Passphrases do not match");
                    std::process::exit(1);
                }
            }

            let request = tonic::Request::new(InitRequest {
                passphrase,
                confirm,
            });
            
            match client.init(request).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    if resp.success {
                        println!("Keystore initialized successfully.");
                        println!("  {}", resp.message);
                    } else {
                        eprintln!("Initialization failed: {}", resp.message);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to initialize keystore: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Pkcs11 { module } => {
            // Already handled above - this is a fallback
            unreachable!("PKCS#11 command should be handled before daemon connection");
        }
    }
    
    Ok(())
}
