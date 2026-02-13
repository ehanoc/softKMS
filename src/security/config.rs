//! Security configuration

use serde::{Deserialize, Serialize};

/// Security layer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// PBKDF2 iterations for master key derivation
    #[serde(default = "default_pbkdf2_iterations")]
    pub pbkdf2_iterations: u32,

    /// Enable memory locking (mlock)
    #[serde(default = "default_memory_lock")]
    pub memory_lock: bool,

    /// Cache duration in seconds (0 = no caching)
    #[serde(default = "default_cache_duration")]
    pub cache_duration: u64,

    /// Key wrapping algorithm
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
}

impl SecurityConfig {
    /// Create new security config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create config with custom PBKDF2 iterations
    pub fn with_iterations(iterations: u32) -> Self {
        Self {
            pbkdf2_iterations: iterations,
            ..Default::default()
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> crate::security::Result<()> {
        if self.pbkdf2_iterations < 100_000 {
            return Err(crate::security::SecurityError::InvalidPassphrase(format!(
                "PBKDF2 iterations {} is too low. Minimum is 100,000.",
                self.pbkdf2_iterations
            )));
        }

        if self.algorithm != "aes-256-gcm" {
            return Err(crate::security::SecurityError::UnsupportedAlgorithm(
                self.algorithm.clone(),
            ));
        }

        Ok(())
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: default_pbkdf2_iterations(),
            memory_lock: default_memory_lock(),
            cache_duration: default_cache_duration(),
            algorithm: default_algorithm(),
        }
    }
}

fn default_pbkdf2_iterations() -> u32 {
    210_000 // OWASP recommended minimum
}

fn default_memory_lock() -> bool {
    true
}

fn default_cache_duration() -> u64 {
    300 // 5 minutes
}

fn default_algorithm() -> String {
    "aes-256-gcm".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SecurityConfig::default();
        assert_eq!(config.pbkdf2_iterations, 210_000);
        assert!(config.memory_lock);
        assert_eq!(config.cache_duration, 300);
        assert_eq!(config.algorithm, "aes-256-gcm");
    }

    #[test]
    fn test_validation_low_iterations() {
        let config = SecurityConfig::with_iterations(50_000);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_invalid_algorithm() {
        let mut config = SecurityConfig::default();
        config.algorithm = "invalid".to_string();
        assert!(config.validate().is_err());
    }
}
