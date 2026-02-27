//! Audit logging module
//! Append-only structured logging in JSON Lines format

#[allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    
    pub timestamp: DateTime<Utc>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_pubkey: Option<String>,
    
    /// Identity type ("admin" or "client")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,
    
    pub action: String,
    
    /// Resource acted upon
    pub resource: String,
    
    pub allowed: bool,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
}

impl AuditEntry {
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
            key_algorithm: None,
            key_type: None,
        }
    }
    
    pub fn with_identity(mut self, pubkey: impl Into<String>, identity_type: impl Into<String>) -> Self {
        self.identity_pubkey = Some(pubkey.into());
        self.identity_type = Some(identity_type.into());
        self
    }
    
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
    
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    pub fn with_key_info(mut self, algorithm: impl Into<String>, key_type: impl Into<String>) -> Self {
        self.key_algorithm = Some(algorithm.into());
        self.key_type = Some(key_type.into());
        self
    }
}

pub struct AuditLogger {
    log_file: PathBuf,
    sequence: std::sync::atomic::AtomicU64,
}

impl AuditLogger {

    pub fn new(log_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&log_dir).expect("Failed to create audit directory");
        
        let log_file = log_dir.join("audit.log");
        
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
    
    pub async fn log(&self,
        action: impl Into<String>,
        resource: impl Into<String>,
        allowed: bool,
    ) -> std::io::Result<()> {
        let seq = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        let entry = AuditEntry::new(seq, action, resource, allowed);
        self.write_entry(entry).await
    }
    
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

    fn get_last_sequence(path: &PathBuf) -> Option<u64> {
        use std::io::BufRead;
        
        let file = std::fs::File::open(path).ok()?;
        let reader = std::io::BufReader::new(file);
        
        let last_line = reader.lines().filter_map(|l| l.ok()).last()?;
        let entry: AuditEntry = serde_json::from_str(&last_line).ok()?;
        
        Some(entry.sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
}
