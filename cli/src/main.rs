//! softKMS CLI - Command line interface for softKMS

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "softkms-cli")]
#[command(about = "SoftKMS - Modern Software Key Management System")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Server address
    #[arg(short, long, default_value = "http://localhost:50051")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key
    Generate {
        /// Algorithm (ed25519, ecdsa, rsa)
        #[arg(short, long)]
        algorithm: String,
        
        /// Key label
        #[arg(short, long)]
        label: Option<String>,
    },
    
    /// List all keys
    List {
        /// Show detailed information
        #[arg(short, long)]
        detailed: bool,
    },
    
    /// Sign data with a key
    Sign {
        /// Key ID
        #[arg(short, long)]
        key: String,
        
        /// Data to sign (base64)
        #[arg(short, long)]
        data: String,
    },
    
    /// Import a seed
    ImportSeed {
        /// Seed mnemonic
        #[arg(short, long)]
        mnemonic: String,
        
        /// Label for the seed
        #[arg(short, long)]
        label: Option<String>,
    },
    
    /// Derive a key from seed
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
        /// Key ID
        #[arg(short, long)]
        key: String,
        
        /// Force deletion without confirmation
        #[arg(short, long)]
        force: bool,
    },
    
    /// Show key information
    Info {
        /// Key ID
        #[arg(short, long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate { algorithm, label } => {
            println!("Generating {} key...", algorithm);
            if let Some(label) = label {
                println!("Label: {}", label);
            }
            // TODO: Implement gRPC call
            println!("Key generated: <key-id>");
        }
        Commands::List { detailed } => {
            println!("Listing keys...");
            if detailed {
                println!("(detailed view)");
            }
            // TODO: Implement gRPC call
            println!("Keys: []");
        }
        Commands::Sign { key, data } => {
            println!("Signing with key: {}", key);
            println!("Data: {}", data);
            // TODO: Implement gRPC call
            println!("Signature: <signature>");
        }
        Commands::ImportSeed { mnemonic, label } => {
            println!("Importing seed...");
            if let Some(label) = label {
                println!("Label: {}", label);
            }
            println!("Mnemonic: {}...", &mnemonic[..20.min(mnemonic.len())]);
            // TODO: Implement gRPC call
            println!("Seed imported: <seed-id>");
        }
        Commands::Derive { seed, path, label } => {
            println!("Deriving key from seed: {}", seed);
            println!("Path: {}", path);
            if let Some(label) = label {
                println!("Label: {}", label);
            }
            // TODO: Implement gRPC call
            println!("Key derived: <key-id>");
        }
        Commands::Delete { key, force } => {
            if !force {
                println!("Are you sure you want to delete key {}? Use --force to confirm.", key);
                return Ok(());
            }
            println!("Deleting key: {}", key);
            // TODO: Implement gRPC call
            println!("Key deleted");
        }
        Commands::Info { key } => {
            println!("Key info: {}", key);
            // TODO: Implement gRPC call
            println!("  Algorithm: ed25519");
            println!("  Created: 2024-01-01");
            println!("  Label: My Key");
        }
    }
    
    Ok(())
}
