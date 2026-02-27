//! softKMS daemon - Main entry point
//!
//! This is the main entry point for the softKMS daemon.

use clap::Parser;
use softkms::{Config, Result, audit::AuditLogger};
use std::path::PathBuf;
use tracing::info;

/// Get default PID file path
/// Uses ~/.softKMS/run/softkms.pid for user-local installation
fn get_default_pid_file() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join(".softKMS")
        .join("run")
        .join("softkms.pid")
}

/// softKMS daemon CLI arguments
#[derive(Parser, Debug)]
#[command(name = "softkms-daemon")]
#[command(about = "softKMS - Modern Software Key Management System")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Storage path (overrides config)
    #[arg(long, value_name = "PATH")]
    storage_path: Option<PathBuf>,

    /// gRPC bind address (overrides config)
    #[arg(long, value_name = "ADDR")]
    grpc_addr: Option<String>,

    /// REST bind address (overrides config)
    #[arg(long, value_name = "ADDR")]
    rest_addr: Option<String>,

    /// Audit storage location (overrides config)
    #[arg(long, value_name = "AUDIT_PATH")]
    audit_storage: Option<PathBuf>,

    /// PID file path [default: ~/.softKMS/run/softkms.pid]
    #[arg(long, value_name = "FILE")]
    pid_file: Option<PathBuf>,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    foreground: bool,

    /// Log level
    #[arg(short, long, value_name = "LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Initialize logging
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::new(format!(
                "softkms={},tower=warn,hyper=warn",
                args.log_level
            )),
        )
        .init();

    info!("Starting softKMS daemon v{}", env!("CARGO_PKG_VERSION"));

    AuditLogger::new(args.audit_storage.clone().unwrap_or_else(|| {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
            .join(".softKMS")
            .join("audit")
    })).log("daemon_start", "softkms-daemon", true).await?;

    // Load configuration
    let mut config = load_config(&args).await?;
    info!("Configuration loaded from: {:?}", args.config);

    // Apply CLI overrides
    if let Some(storage_path) = args.storage_path {
        config.storage.path = storage_path;
        info!("Storage path override: {:?}", config.storage.path);
    }
    if let Some(grpc_addr) = args.grpc_addr {
        config.api.grpc_addr = grpc_addr;
        info!("gRPC address override: {}", config.api.grpc_addr);
    }
    if let Some(rest_addr) = args.rest_addr {
        config.api.rest_addr = Some(rest_addr);
        info!("REST address override: {:?}", config.api.rest_addr);
    }

    // look for audit storage location in config and log it
    if let Some(audit_storage) = args.audit_storage {
        info!("Audit storage location: {:?}", audit_storage);
    }

    // Get PID file path (use default if not specified)
    let pid_file = args.pid_file.unwrap_or_else(get_default_pid_file);
    
    // Create PID directory if it doesn't exist
    if let Some(parent) = pid_file.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                softkms::Error::Internal(format!("Failed to create PID directory: {}", e))
            })?;
        }
    }

    // Start daemon
    info!("Initializing daemon...");
    let daemon = softkms::daemon::Daemon::new(config).await?;
    let daemon = daemon.with_pid_file(pid_file);

    // If not running in foreground, we would daemonize here
    // For now, just run directly
    if !args.foreground {
        info!("Running in daemon mode (background)");
        // TODO: Implement actual daemonization on Unix
        // For now, just log it
    } else {
        info!("Running in foreground mode");
    }

    daemon.start().await
}

async fn load_config(args: &Args) -> Result<Config> {
    if let Some(config_path) = &args.config {
        // Load from file
        let content = std::fs::read_to_string(config_path).map_err(|e| {
            softkms::Error::Storage(format!("Failed to read config file: {}", e))
        })?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            softkms::Error::InvalidParams(format!("Failed to parse config file: {}", e))
        })?;

        Ok(config)
    } else {
        // Use default config
        info!("No config file specified, using defaults");
        Ok(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test that CLI args can be parsed
        let args = Args::parse_from(["softkms-daemon", "--foreground"]);
        assert!(args.foreground);
        assert_eq!(args.log_level, "info");
    }
}
