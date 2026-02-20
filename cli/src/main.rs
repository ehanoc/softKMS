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
    CreateIdentityRequest, ListIdentitiesRequest, RevokeIdentityRequest, GetIdentityRequest,
    ClientType, IdentityKeyType,
};
use softkms::api::softkms::identity_service_client::IdentityServiceClient;

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
    
    /// Identity token for authentication (alternative to passphrase for identity-scoped operations)
    #[arg(short = 't', long)]
    token: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key
    Generate {
        /// Algorithm (ed25519, p256, ecdsa, rsa)
        #[arg(short, long)]
        algorithm: String,

        /// Human-readable label
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

        /// Data that was signed
        #[arg(short, long)]
        data: String,

        /// Signature to verify (base64 encoded)
        #[arg(short, long)]
        signature: String,

        /// Data encoding: raw (default) or hex
        #[arg(long, default_value = "raw")]
        encoding: String,
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

    /// Import a BIP39 seed phrase
    ImportSeed {
        /// BIP39 mnemonic phrase (12-24 words)
        #[arg(short, long)]
        mnemonic: String,

        /// Human-readable label
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Derive a key from seed (BIP32)
    Derive {
        /// Algorithm to derive (ed25519, p256)
        #[arg(short, long)]
        algorithm: String,

        /// Seed ID to derive from
        #[arg(short, long)]
        seed: String,

        /// Derivation path (e.g., "m/44'/283'/0'/0/0")
        #[arg(short, long)]
        path: String,

        /// Derivation scheme: v2 or peikert
        #[arg(long, default_value = "v2")]
        scheme: String,

        /// Origin/domain for derivation (e.g., "github.com")
        #[arg(long)]
        origin: Option<String>,

        /// User handle for derivation
        #[arg(long)]
        user_handle: Option<String>,

        /// Counter for multiple keys per origin
        #[arg(long, default_value = "0")]
        counter: u32,

        /// Label for derived key
        #[arg(short, long)]
        label: Option<String>,
    },

    /// Identity management commands
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    /// Create a new identity
    Create {
        /// Identity type: ai-agent, service, user, pkcs11
        #[arg(short, long)]
        r#type: String,

        /// Description of the identity
        #[arg(short, long)]
        description: Option<String>,
    },

    /// List all identities
    List {
        /// Include inactive identities
        #[arg(long)]
        include_inactive: bool,
    },

    /// Show identity details
    Info {
        /// Public key of the identity (base64 encoded)
        #[arg(short, long)]
        public_key: String,
    },

    /// Revoke an identity
    Revoke {
        /// Public key of the identity to revoke
        #[arg(short, long)]
        public_key: String,

        /// Force revocation without confirmation
        #[arg(short, long)]
        force: bool,
    },
}

/// Lookup key ID by label
async fn lookup_key_by_label(
    client: &mut KeyStoreClient<tonic::transport::Channel>,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = tonic::Request::new(ListKeysRequest {
        include_public_keys: false,
        auth_token: String::new(),
    });

    let response = client.list_keys(request).await?;
    let list = response.into_inner();

    let matching_keys: Vec<_> = list.keys.iter()
        .filter(|k| k.label.as_deref() == Some(label))
        .collect();

    match matching_keys.len() {
        0 => Err(format!("No key found with label '{}'", label).into()),
        1 => Ok(matching_keys[0].key_id.clone()),
        _ => {
            eprintln!("Multiple keys found with label '{}'", label);
            for k in matching_keys {
                println!("  {} (created: {})", k.key_id, k.created_at);
            }
            Err("Ambiguous label - use --key with the UUID".into())
        }
    }
}

/// Get authentication credentials - either token or passphrase
/// Token takes precedence if both are provided
fn get_auth_credentials(
    cli_token: Option<String>,
    cli_pass: Option<String>,
) -> Result<(Option<String>, Option<String>), Box<dyn std::error::Error>> {
    // Token takes precedence
    if let Some(token) = cli_token {
        if !token.is_empty() {
            return Ok((Some(token), None));
        }
    }
    
    // Fall back to passphrase
    if let Some(pass) = cli_pass {
        if pass.is_empty() {
            return Err("Passphrase cannot be empty".into());
        }
        return Ok((None, Some(pass)));
    }
    
    // Prompt for passphrase interactively
    let passphrase = prompt_password("Enter passphrase: ")?;
    if passphrase.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }
    Ok((None, Some(passphrase)))
}

/// Get authentication for gRPC requests - returns (auth_token, passphrase)
/// Exits with error if neither is provided
fn get_grpc_auth(
    cli_token: Option<String>,
    cli_passphrase: Option<String>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    match get_auth_credentials(cli_token, cli_passphrase)? {
        (Some(token), _) => Ok((token, String::new())),
        (_, Some(pass)) => Ok((String::new(), pass)),
        _ => {
            eprintln!("Either --token or --passphrase must be provided");
            std::process::exit(1);
        }
    }
}

/// Get passphrase-only auth (for commands that don't support tokens)
fn get_passphrase_auth(
    cli_token: Option<String>,
    cli_passphrase: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(token) = cli_token {
        if !token.is_empty() {
            eprintln!("Token-based auth not supported for this operation");
            std::process::exit(1);
        }
    }
    
    if let Some(pass) = cli_passphrase {
        if !pass.is_empty() {
            return Ok(pass);
        }
        return Err("Passphrase cannot be empty".into());
    }
    
    let passphrase = prompt_password("Enter passphrase: ")?;
    if passphrase.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }
    Ok(passphrase)
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

    // Connect to daemon
    let mut client = KeyStoreClient::connect(cli.server.clone()).await?;
    let mut identity_client = IdentityServiceClient::connect(cli.server).await?;

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

                let passphrase = get_passphrase_auth(
                    cli.token.clone(),
                    cli.passphrase.clone(),
                )?;
                
                let request = tonic::Request::new(DeriveP256Request {
                    seed_id: seed_id.clone(),
                    origin: origin.clone(),
                    user_handle: user_handle.clone(),
                    counter,
                    label,
                    passphrase,
                    auth_token: String::new(), // HD derivation from generate command doesn't support tokens yet
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
                let (auth_token, passphrase) = get_grpc_auth(
                    cli.token.clone(),
                    cli.passphrase.clone(),
                )?;

                let request = tonic::Request::new(CreateKeyRequest {
                    algorithm: algorithm.clone(),
                    label,
                    attributes: std::collections::HashMap::new(),
                    auth_token,
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
            let (auth_token, _passphrase) = get_grpc_auth(
                cli.token.clone(),
                cli.passphrase.clone(),
            )?;
            
            let request = tonic::Request::new(ListKeysRequest {
                include_public_keys: true,
                auth_token,
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
                            if let Some(ref pk) = key.public_key {
                                println!("    Public Key: {}...", &pk[..50.min(pk.len())]);
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
            
            let (auth_token, passphrase) = get_grpc_auth(
                cli.token.clone(),
                cli.passphrase.clone(),
            )?;

            let data_bytes = if let Ok(decoded) = BASE64.decode(&data) {
                decoded
            } else {
                data.as_bytes().to_vec()
            };

            let request = tonic::Request::new(SignRequest {
                key_id: key_id.clone(),
                data: data_bytes,
                passphrase,
                auth_token,
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

        Commands::Verify { key, label, data, signature, encoding: _ } => {
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

            let signature_bytes = BASE64.decode(&signature)
                .map_err(|e| format!("Invalid base64 signature: {}", e))?;

            let request = tonic::Request::new(VerifyRequest {
                key_id: key_id.clone(),
                data: data_bytes,
                signature: signature_bytes,
            });

            match client.verify(request).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    if resp.valid {
                        println!("Signature verified successfully");
                        println!("VALID");
                        println!("Algorithm: {}", resp.algorithm);
                    } else {
                        println!("Signature is INVALID");
                        println!("INVALID");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Signature verification failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Info { key, label } => {
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

            let (auth_token, _passphrase) = get_grpc_auth(
                cli.token.clone(),
                cli.passphrase.clone(),
            )?;

            let request = tonic::Request::new(GetKeyRequest {
                key_id: key_id.clone(),
                include_public_key: true,
                auth_token,
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
                            println!("  Public Key: {}", pk);
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

        Commands::Init { confirm } => {
            let passphrase = get_passphrase_auth(
                cli.token.clone(),
                cli.passphrase.clone(),
            )?;

            if confirm {
                let confirm_pass = prompt_password("Confirm passphrase: ")?;
                if passphrase != confirm_pass {
                    eprintln!("Passphrases do not match");
                    std::process::exit(1);
                }
            }

            let request = tonic::Request::new(InitRequest {
                passphrase: passphrase.clone(),
                confirm: confirm.clone(),
            });

            match client.init(request).await {
                Ok(_) => {
                    println!("Keystore initialized successfully.");
                }
                Err(e) => {
                    eprintln!("Failed to initialize keystore: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Pkcs11 { .. } => {
            // Handled above before connecting to daemon
        }

        Commands::ImportSeed { mnemonic, label } => {
            let (auth_token, passphrase) = get_grpc_auth(
                cli.token.clone(),
                cli.passphrase.clone(),
            )?;

            let request = tonic::Request::new(ImportSeedRequest {
                mnemonic,
                label,
                passphrase,
                auth_token,
            });

            match client.import_seed(request).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    println!("Seed imported successfully:");
                    println!("  Seed ID: {}", resp.seed_id);
                    println!("  Created: {}", resp.created_at);
                }
                Err(e) => {
                    eprintln!("Failed to import seed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Derive { algorithm, seed, path, scheme, origin, user_handle, counter, label } => {
            let (auth_token, passphrase) = get_grpc_auth(
                cli.token.clone(),
                cli.passphrase.clone(),
            )?;

            let derivation_scheme = match scheme.as_str() {
                "v2" => DerivationScheme::V2,
                _ => DerivationScheme::Peikert,
            };

            match algorithm.as_str() {
                "p256" => {
                    let origin = origin.unwrap_or_default();
                    let user_handle = user_handle.unwrap_or_default();
                    
                    let request = tonic::Request::new(DeriveP256Request {
                        seed_id: seed,
                        origin,
                        user_handle,
                        counter,
                        label,
                        passphrase,
                        auth_token: auth_token.clone(),
                    });

                    match client.derive_p256(request).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            println!("P-256 key derived successfully:");
                            println!("  Key ID: {}", resp.key_id);
                            println!("  Algorithm: {}", resp.algorithm);
                            println!("  Public Key (base64): {}...", &resp.public_key[..50.min(resp.public_key.len())]);
                            println!("  Created: {}", resp.created_at);
                        }
                        Err(e) => {
                            eprintln!("Failed to derive P-256 key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                "ed25519" => {
                    // Extract coin type from BIP44 path (m/44'/coin_type'/...)
                    let coin_type: u32 = path.split('/').nth(2)
                        .and_then(|s| s.trim_end_matches('\'').parse().ok())
                        .unwrap_or(283);
                    
                    let request = tonic::Request::new(DeriveEd25519Request {
                        seed_id: seed,
                        derivation_path: path,
                        coin_type,
                        scheme: derivation_scheme as i32,
                        store_key: true,
                        label,
                        passphrase,
                        auth_token,
                    });

                    match client.derive_ed25519(request).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            println!("Ed25519 key derived successfully:");
                            println!("  Key ID: {}", resp.key_id);
                            println!("  Algorithm: {}", resp.algorithm);
                            println!("  Public Key (base64): {}...", &resp.public_key[..50.min(resp.public_key.len())]);
                            println!("  Created: {}", resp.created_at);
                        }
                        Err(e) => {
                            eprintln!("Failed to derive Ed25519 key: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    eprintln!("Unsupported algorithm for derivation: {}", algorithm);
                    std::process::exit(1);
                }
            }
        }

        Commands::Identity { command } => {
            match command {
                IdentityCommands::Create { r#type, description } => {
                    let passphrase = get_passphrase_auth(
                        cli.token.clone(),
                        cli.passphrase.clone(),
                    )?;

                    let client_type = match r#type.as_str() {
                        "ai-agent" => ClientType::AiAgent,
                        "service" => ClientType::Service,
                        "user" => ClientType::User,
                        "pkcs11" => ClientType::Pkcs11,
                        _ => {
                            eprintln!("Invalid identity type: {}", r#type);
                            std::process::exit(1);
                        }
                    };

                    let key_type = match client_type {
                        ClientType::Pkcs11 => IdentityKeyType::P256,
                        _ => IdentityKeyType::Ed25519,
                    };

                    let request = tonic::Request::new(CreateIdentityRequest {
                        client_type: client_type as i32,
                        key_type: key_type as i32,
                        description,
                        passphrase,
                    });

                    match identity_client.create_identity(request).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            println!("Identity created successfully:");
                            println!("  Token: {}", resp.token);
                            println!("  Public Key: {}", resp.public_key);
                            println!("  Created: {}", resp.created_at);
                            println!("");
                            println!("IMPORTANT: Store the token securely - it will not be shown again!");
                        }
                        Err(e) => {
                            eprintln!("Failed to create identity: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                IdentityCommands::List { include_inactive } => {
                    let passphrase = get_passphrase_auth(
                        cli.token.clone(),
                        cli.passphrase.clone(),
                    )?;

                    let request = tonic::Request::new(ListIdentitiesRequest {
                        include_inactive,
                        passphrase,
                    });

                    match identity_client.list_identities(request).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            let count = resp.identities.len();
                            if resp.identities.is_empty() {
                                println!("No identities found.");
                            } else {
                                println!("Identities:");
                                for identity in resp.identities {
                                    println!("  Public Key: {}", identity.public_key);
                                    println!("    Type: {:?}", identity.client_type);
                                    println!("    Status: {}", if identity.is_active { "active" } else { "inactive" });
                                    if !identity.description.is_empty() {
                                        println!("    Description: {}", identity.description);
                                    }
                                    println!("    Created: {}", identity.created_at);
                                    if !identity.last_used.is_empty() {
                                        println!("    Last Used: {}", identity.last_used);
                                    }
                                    println!();
                                }
                                println!("Total: {} identities", count);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to list identities: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                IdentityCommands::Info { public_key } => {
                    // Identity info needs token for auth
                    let token = match cli.token.clone() {
                        Some(token) => token,
                        _ => {
                            eprintln!("Token required for identity info");
                            std::process::exit(1);
                        }
                    };

                    let request = tonic::Request::new(GetIdentityRequest {
                        public_key: public_key.clone(),
                        token,
                    });

                    match identity_client.get_identity(request).await {
                        Ok(response) => {
                            let resp = response.into_inner();
                            if let Some(identity) = resp.identity {
                                println!("Identity Information:");
                                println!("  Public Key: {}", identity.public_key);
                                println!("  Type: {:?}", identity.client_type);
                                println!("  Status: {}", if identity.is_active { "active" } else { "inactive" });
                                if !identity.description.is_empty() {
                                    println!("  Description: {}", identity.description);
                                }
                                println!("  Created: {}", identity.created_at);
                                if !identity.last_used.is_empty() {
                                    println!("  Last Used: {}", identity.last_used);
                                }
                            } else {
                                println!("Identity {} not found.", public_key);
                                std::process::exit(1);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to get identity info: {}", e);
                            std::process::exit(1);
                        }
                    }
                }

                IdentityCommands::Revoke { public_key, force } => {
                    if !force {
                        println!("Are you sure you want to revoke identity {}?", public_key);
                        println!("This action cannot be undone. Use --force to confirm.");
                        std::process::exit(1);
                    }

                    let passphrase = get_passphrase_auth(
                        cli.token.clone(),
                        cli.passphrase.clone(),
                    )?;

                    let request = tonic::Request::new(RevokeIdentityRequest {
                        public_key: public_key.clone(),
                        passphrase,
                        force,
                    });

                    match identity_client.revoke_identity(request).await {
                        Ok(_) => {
                            println!("Identity {} revoked successfully.", public_key);
                        }
                        Err(e) => {
                            eprintln!("Failed to revoke identity: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        Commands::Health => {
            // Health check doesn't need authentication
            let request = tonic::Request::new(HealthRequest {});
            match client.health(request).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    println!("Health check passed");
                    println!("  Status: {}", if resp.healthy { "healthy" } else { "unhealthy" });
                    if !resp.version.is_empty() {
                        println!("  Version: {}", resp.version);
                    }
                    println!("  Storage Ready: {}", resp.storage_ready);
                    println!("  API Ready: {}", resp.api_ready);
                    println!("  Initialized: {}", resp.initialized);
                }
                Err(e) => {
                    eprintln!("Health check failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
