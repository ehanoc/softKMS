//! Daemon module - Main daemon logic
//!
//! This module handles the daemon lifecycle:
//! 1. Initialize storage backend
//! 2. Start API servers (gRPC, REST)
//! 3. Handle graceful shutdown
//! 4. Manage PID file
//! 5. Health checks

use crate::storage::file::FileStorage;
use crate::storage::StorageBackend;
use crate::{Config, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

/// Daemon state
pub struct Daemon {
    config: Config,
    storage: Arc<dyn StorageBackend>,
    pid_file: Option<PathBuf>,
}

impl Daemon {
    /// Create a new daemon instance
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize storage backend
        let storage: Arc<dyn StorageBackend> = match config.storage.backend.as_str() {
            "file" => {
                let file_storage =
                    FileStorage::new(config.storage.path.clone(), config.clone());
                file_storage.init().await?;
                info!("Initialized file storage at {:?}", config.storage.path);
                Arc::new(file_storage)
            }
            _ => {
                return Err(crate::Error::Storage(format!(
                    "Unknown storage backend: {}",
                    config.storage.backend
                )));
            }
        };

        Ok(Self {
            config,
            storage,
            pid_file: None,
        })
    }

    /// Set PID file path
    pub fn with_pid_file(mut self, path: PathBuf) -> Self {
        self.pid_file = Some(path);
        self
    }

    /// Write PID file
    fn write_pid_file(&self) -> Result<()> {
        if let Some(ref pid_file) = self.pid_file {
            let pid = std::process::id();
            std::fs::write(pid_file, pid.to_string())
                .map_err(|e| crate::Error::Internal(format!("Failed to write PID file: {}", e)))?;
            info!("Wrote PID file: {}", pid_file.display());
        }
        Ok(())
    }

    /// Remove PID file
    fn remove_pid_file(&self) {
        if let Some(ref pid_file) = self.pid_file {
            let _ = std::fs::remove_file(pid_file);
        }
    }

    /// Check if another instance is running
    fn check_existing_instance(&self) -> Result<bool> {
        if let Some(ref pid_file) = self.pid_file {
            if pid_file.exists() {
                let content = std::fs::read_to_string(pid_file)
                    .map_err(|e| crate::Error::Internal(format!("Failed to read PID file: {}", e)))?;
                
                if let Ok(pid) = content.trim().parse::<u32>() {
                    // Check if process exists (Linux-specific)
                    #[cfg(target_os = "linux")]
                    {
                        let proc_path = format!("/proc/{}", pid);
                        if std::path::Path::new(&proc_path).exists() {
                            // Also check it's not our own PID (we might be restarting)
                            if pid != std::process::id() {
                                return Ok(true);
                            }
                        }
                    }
                    
                    // If we can't verify or it's our own stale PID, remove it
                    let _ = std::fs::remove_file(pid_file);
                }
            }
        }
        Ok(false)
    }

    /// Start the daemon
    pub async fn start(self) -> Result<()> {
        info!("Starting softKMS daemon v{}", env!("CARGO_PKG_VERSION"));

        // Check for existing instance
        if self.check_existing_instance()? {
            return Err(crate::Error::Internal(
                "Another instance is already running".to_string(),
            ));
        }

        // Write PID file
        self.write_pid_file()?;

        // Start API servers
        let api_handle = self.start_api_servers().await?;

        // Setup signal handlers
        let shutdown = self.setup_shutdown_handler();

        info!("Daemon started successfully");
        info!("gRPC API listening on {}", self.config.api.grpc_addr);
        if let Some(ref rest_addr) = self.config.api.rest_addr {
            info!("REST API listening on {}", rest_addr);
        }

        // Wait for shutdown signal
        shutdown.await;

        // Graceful shutdown
        info!("Shutting down daemon...");
        
        // Stop API servers
        drop(api_handle);
        
        // Cleanup
        self.remove_pid_file();

        info!("Daemon stopped");
        Ok(())
    }

    /// Start API servers
    async fn start_api_servers(&self,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            // Start gRPC server
            if let Err(e) = crate::api::grpc::start(&config).await {
                error!("gRPC server error: {}", e);
            }
        });

        // Start REST server if enabled
        if let Some(ref _rest_addr) = self.config.api.rest_addr {
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::api::rest::start(&config).await {
                    error!("REST server error: {}", e);
                }
            });
        }

        Ok(handle)
    }

    /// Setup shutdown signal handler
    fn setup_shutdown_handler(&self,
    ) -> impl std::future::Future<Output = ()> {
        async {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to create SIGTERM handler");
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Failed to create SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, starting shutdown...");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, starting shutdown...");
                }
            }
        }
    }
}

/// Start the daemon (public API)
pub async fn start(config: Config) -> Result<()> {
    let daemon = Daemon::new(config).await?;
    
    // Use default PID file location
    let pid_file = PathBuf::from("/var/run/softkms/softkms.pid");
    let daemon = daemon.with_pid_file(pid_file);
    
    daemon.start().await
}

/// Health check status
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub healthy: bool,
    pub storage_ready: bool,
    pub api_ready: bool,
    pub version: String,
}

impl HealthStatus {
    /// Create a new health status
    pub fn new() -> Self {
        Self {
            healthy: false,
            storage_ready: false,
            api_ready: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Check if daemon is healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy && self.storage_ready && self.api_ready
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_daemon_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.storage.path = temp_dir.path().join("storage");
        
        let result = Daemon::new(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_health_status() {
        let mut status = HealthStatus::new();
        assert!(!status.is_healthy());
        
        status.healthy = true;
        status.storage_ready = true;
        status.api_ready = true;
        assert!(status.is_healthy());
    }
}
