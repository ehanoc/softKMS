//! PKCS#11 configuration module
//!
//! Configuration is loaded from:
//! 1. SOFTKMS_PKCS11_CONFIG environment variable (explicit path)
//! 2. $XDG_CONFIG_HOME/softkms/pkcs11.conf (user config)
//! 3. ~/.config/softkms/pkcs11.conf (fallback user config)
//! 4. /etc/softkms/pkcs11.conf (system-wide)
//! 5. Built-in defaults

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// PKCS#11 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11Config {
    /// Daemon server address
    pub daemon_addr: String,
    /// Slot description for PKCS#11
    pub slot_description: String,
    /// Token label
    pub token_label: String,
    /// Enable debug logging
    pub debug: bool,
}

impl Default for Pkcs11Config {
    fn default() -> Self {
        Self {
            daemon_addr: "127.0.0.1:50051".to_string(),
            slot_description: "softKMS".to_string(),
            token_label: "softKMS Token".to_string(),
            debug: false,
        }
    }
}

impl Pkcs11Config {
    /// Load configuration with automatic discovery
    pub fn load() -> Self {
        // Check environment variable first
        if let Ok(config_path) = std::env::var("SOFTKMS_PKCS11_CONFIG") {
            let path = PathBuf::from(config_path);
            if let Ok(config) = Self::load_from_file(&path) {
                return config;
            }
        }

        // Search standard paths
        let search_paths: Vec<PathBuf> = vec![
            // XDG config
            dirs::config_dir()
                .map(|d| d.join("softkms").join("pkcs11.conf"))
                .unwrap_or_default(),
            // Fallback home config
            dirs::home_dir()
                .map(|d| d.join(".config").join("softkms").join("pkcs11.conf"))
                .unwrap_or_default(),
            // System-wide
            PathBuf::from("/etc/softkms/pkcs11.conf"),
        ];

        for path in search_paths {
            if path.exists() {
                if let Ok(config) = Self::load_from_file(&path) {
                    return config;
                }
            }
        }

        // Use defaults
        Self::default()
    }

    /// Load configuration from a specific file
    fn load_from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Pkcs11Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Get daemon address (with environment override)
    pub fn get_daemon_addr(&self) -> String {
        std::env::var("SOFTKMS_DAEMON_ADDR").unwrap_or_else(|_| self.daemon_addr.clone())
    }
}

/// Global configuration (lazy-loaded)
use once_cell::sync::Lazy;
static CONFIG: Lazy<Pkcs11Config> = Lazy::new(Pkcs11Config::load);

/// Get the global configuration
pub fn get_config() -> &'static Pkcs11Config {
    &CONFIG
}

/// Get daemon address (checks env var first, then config)
pub fn get_daemon_addr() -> String {
    get_config().get_daemon_addr()
}
