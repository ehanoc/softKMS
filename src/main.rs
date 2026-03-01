//! softKMS daemon - Main entry point
//!
//! This is the main entry point for the softKMS daemon.

use clap::Parser;
use softkms::{Config, Result, RunMode, audit::AuditLogger};
use std::path::PathBuf;
use tracing::info;

/// Get default PID file path based on run mode
fn get_default_pid_file(mode: RunMode) -> PathBuf {
    match mode {
        RunMode::System => PathBuf::from("/run/softkms/softkms.pid"),
        _ => {
            // User mode - try XDG_RUNTIME_DIR, then /tmp
            std::env::var("XDG_RUNTIME_DIR")
                .map(|d| PathBuf::from(d).join("softkms.pid"))
                .unwrap_or_else(|_| PathBuf::from("/tmp/softkms.pid"))
        }
    }
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

    /// Force user mode (XDG paths: ~/.config/, ~/.local/share/)
    #[arg(long, conflicts_with = "system")]
    user: bool,

    /// Force system mode (/etc, /var paths)
    #[arg(long, conflicts_with = "user")]
    system: bool,

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

    /// PID file path [default: based on run mode]
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

    // Determine run mode from CLI flags
    let mode = if args.system {
        RunMode::System
    } else if args.user {
        RunMode::User
    } else {
        RunMode::Auto
    };

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::new(format!(
                "softkms={},tower=warn,hyper=warn",
                args.log_level
            )),
        )
        .init();

    info!("Starting softKMS daemon v{}", env!("CARGO_PKG_VERSION"));
    info!("Run mode: {:?}", mode);

    // Load configuration with mode detection
    let mut config = Config::load(args.config.clone(), mode)?;
    
    // Log which config file was used
    if let Some(ref config_path) = args.config {
        info!("Configuration loaded from: {}", config_path.display());
    } else {
        info!("Using discovered or default configuration");
    }
    info!("Data directory: {}", config.data_dir().display());
    if let Some(audit_path) = config.audit_path() {
        info!("Audit log: {}", audit_path.display());
    }

    // Apply CLI overrides
    if let Some(storage_path) = args.storage_path {
        config.storage.path = storage_path;
        info!("Storage path override: {}", config.storage.path.display());
    }
    if let Some(grpc_addr) = args.grpc_addr {
        config.api.grpc_addr = grpc_addr;
        info!("gRPC address override: {}", config.api.grpc_addr);
    }
    if let Some(rest_addr) = args.rest_addr {
        let rest_addr_clone = rest_addr.clone();
        config.api.rest_addr = Some(rest_addr);
        info!("REST address override: {}", rest_addr_clone);
    }

    // look for audit storage location in config and log it
    if let Some(audit_storage) = args.audit_storage {
        info!("Audit storage location: {}", audit_storage.display());
    }

    // Get PID file path based on mode
    let pid_file = args.pid_file.unwrap_or_else(|| get_default_pid_file(config.run_mode));
    info!("PID file: {}", pid_file.display());
    
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

// load_config is now handled by Config::load()
// Kept for backwards compatibility in tests
#[cfg(test)]
async fn load_config(_args: &Args) -> Result<Config> {
    Ok(Config::default())
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
