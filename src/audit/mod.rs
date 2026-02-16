//! Audit logging module
//!
//! Append-only structured logging in JSON Lines format

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number
    pub sequence: u64,
    
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Identity public key (if authenticated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_pubkey: Option<String>,
    
    /// Identity type ("admin" or "client")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
    
    /// Action performed
    pub action: String,
    
    /// Resource acted upon
    pub resource: String,
    
    /// Whether action was allowed
    pub allowed: bool,
    
    /// Reason if denied
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    
    /// Source IP (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(
        sequence: u64,
        action: impl Into<String>,
        resource: impl Into<String>,
        allowed: bool,
    ) -> Self {
        Self {
            sequence,
            timestamp: Utc::now(),
            identity_pubkey: None,
            identity_type: None,
            action: action.into(),
            resource: resource.into(),
            allowed,
            reason: None,
            source_ip: None,
        }
    }
    
    /// Set identity
    pub fn with_identity(mut self, pubkey: impl Into<String>, identity_type: impl Into<String>) -> Self {
        self.identity_pubkey = Some(pubkey.into());
        self.identity_type = Some(identity_type.into());
        self
    }
    
    /// Set denial reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
    
    /// Set source IP
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }
}

/// Audit logger
pub struct AuditLogger {
    log_file: PathBuf,
    sequence: std::sync::atomic::AtomicU64,
}

impl AuditLogger {
    /// Create new audit logger
    pub fn new(log_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&log_dir).expect("Failed to create audit directory");
        
        let log_file = log_dir.join("audit.log");
        
        // Get current sequence
        let sequence = if log_file.exists() {
            Self::get_last_sequence(&log_file).unwrap_or(0) + 1
        } else {
            1
        };
        
        Self {
            log_file,
            sequence: std::sync::atomic::AtomicU64::new(sequence),
        }
    }
    
    /// Log an entry
    pub async fn log(&self,
        action: impl Into<String>,
        resource: impl Into<String>,
        allowed: bool,
    ) -> std::io::Result<()> {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        let entry = AuditEntry::new(seq, action, resource, allowed);
        self.write_entry(entry).await
    }
    
    /// Log with identity
    pub async fn log_with_identity(
        &self,
        identity_pubkey: &str,
        identity_type: &str,
        action: impl Into<String>,
        resource: impl Into<String>,
        allowed: bool,
    ) -> std::io::Result<()> {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        let entry = AuditEntry::new(seq, action, resource, allowed)
            .with_identity(identity_pubkey, identity_type);
        
        self.write_entry(entry).await
    }
    
    /// Log denied access
    pub async fn log_denied(
        &self,
        identity_pubkey: &str,
        action: &str,
        resource: &str,
        reason: &str,
    ) -> std::io::Result<()> {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        let entry = AuditEntry::new(seq, action, resource, false)
            .with_identity(identity_pubkey, "client")
            .with_reason(reason);
        
        self.write_entry(entry).await
    }
    
    /// Write entry to log file
    async fn write_entry(&self,
        entry: AuditEntry,
    ) -> std::io::Result<()> {
        let json = serde_json::to_string(&entry)?;
        
        // Append to file with newline
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
            .await?;
        
        tokio::io::AsyncWriteExt::write_all(&mut file, json.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, b"\n").await?;
        
        Ok(())
    }
    
    /// Get last sequence number from file
    fn get_last_sequence(path: &PathBuf) -> Option<u64> {
        use std::io::BufRead;
        
        let file = std::fs::File::open(path).ok()?;
        let reader = std::io::BufReader::new(file);
        
        let last_line = reader.lines().filter_map(|l| l.ok()).last()?;
        let entry: AuditEntry = serde_json::from_str(&last_line).ok()?;
        
        Some(entry.sequence)
    }
    
    /// Query audit log
    pub async fn query(
        &self,
        identity_filter: Option<&str>,
        action_filter: Option<&str>,
        allowed_only: bool,
        limit: usize,
    ) -> std::io::Result<Vec<AuditEntry>> {
        if !self.log_file.exists() {
            return Ok(Vec::new());
        }
        
        let content = tokio::fs::read_to_string(&self.log_file).await?;
        let mut entries = Vec::new();
        
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                // Apply filters
                if let Some(id) = identity_filter {
                    if entry.identity_pubkey.as_deref() != Some(id) {
                        continue;
                    }
                }
                
                if let Some(action) = action_filter {
                    if entry.action != action {
                        continue;
                    }
                }
                
                if allowed_only && !entry.allowed {
                    continue;
                }
                
                entries.push(entry);
                
                if entries.len() >= limit {
                    break;
                }
            }
        }
        
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_log_entry() {
        let temp = TempDir::new().unwrap();
        let logger = AuditLogger::new(temp.path().to_path_buf());
        
        // Log entry
        logger.log("CreateKey", "ed25519:client1/keys/key1", true).await.unwrap();
        
        // Query
        let entries = logger.query(None, None, false, 100).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "CreateKey");
        assert_eq!(entries[0].sequence, 1);
    }
    
    #[tokio::test]
    async fn test_log_with_identity() {
        let temp = TempDir::new().unwrap();
        let logger = AuditLogger::new(temp.path().to_path_buf());
        
        logger.log_with_identity(
            "ed25519:client1",
            "client",
            "Sign",
            "ed25519:client1/keys/key1",
            true,
        ).await.unwrap();
        
        let entries = logger.query(Some("ed25519:client1"), None, false, 100).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].identity_pubkey, Some("ed25519:client1".to_string()));
    }
    
    #[tokio::test]
    async fn test_log_denied() {
        let temp = TempDir::new().unwrap();
        let logger = AuditLogger::new(temp.path().to_path_buf());
        
        logger.log_denied(
            "ed25519:client2",
            "Sign",
            "ed25519:client1/keys/key1",
            "Not owner",
        ).await.unwrap();
        
        let entries = logger.query(None, None, false, 100).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].allowed);
        assert_eq!(entries[0].reason, Some("Not owner".to_string()));
    }
    
    #[tokio::test]
    async fn test_sequence_monotonic() {
        let temp = TempDir::new().unwrap();
        let logger = AuditLogger::new(temp.path().to_path_buf());
        
        // Log multiple entries
        for i in 0..5 {
            logger.log("Test", format!("resource{}", i), true).await.unwrap();
        }
        
        let entries = logger.query(None, None, false, 100).await.unwrap();
        assert_eq!(entries.len(), 5);
        
        // Check sequence is monotonic
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(entry.sequence as usize, i + 1);
        }
    }
}
