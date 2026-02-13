//! Native Messaging Host for Browser Integration
//!
//! Native messaging allows browser extensions to communicate with native applications
//! like softKMS. This module implements the native messaging protocol.
//!
//! ## Protocol
//!
//! Messages are sent using a simple protocol:
//! - First 4 bytes: message length (uint32, native byte order)
//! - Remaining bytes: JSON message
//!
//! ## Chrome Setup
//!
//! A JSON "host manifest" file must be installed in:
//! - Linux: `~/.config/google-chrome/NativeMessagingHosts/com.softkms.webauthn.json`
//! - macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
//! - Windows: `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\`
//!
//! ## Firefox Setup
//!
//! Similar setup with manifest in:
//! - Linux: `~/.mozilla/native-messaging-hosts/`
//!
//! ## Manifest Example
//!
//! ```json
//! {
//!   "name": "com.softkms.webauthn",
//!   "description": "softKMS WebAuthn Authenticator",
//!   "path": "/usr/bin/softkms-webauthn",
//!   "type": "stdio",
//!   "allowed_origins": [
//!     "chrome-extension://<extension-id>/"
//!   ]
//! }
//! ```

use crate::webauthn::WebAuthnConfig;
use crate::webauthn::ctap2::Ctap2Request;
use crate::Result;

/// Native messaging message
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum NativeMessage {
    /// CTAP2 request from browser
    #[serde(rename = "ctap2_request")]
    Ctap2Request {
        /// Request ID
        id: u64,
        /// CTAP2 command data (base64 or CBOR)
        data: String,
    },
    /// CTAP2 response to browser
    #[serde(rename = "ctap2_response")]
    Ctap2Response {
        /// Request ID
        id: u64,
        /// Response data (base64 or CBOR)
        data: String,
        /// Error if any
        error: Option<String>,
    },
    /// Error message
    #[serde(rename = "error")]
    Error {
        /// Error message
        message: String,
        /// Error code
        code: Option<u32>,
    },
    /// Ping/keepalive
    #[serde(rename = "ping")]
    Ping,
    /// Pong response
    #[serde(rename = "pong")]
    Pong,
}

/// Native messaging host
pub struct NativeMessagingHost {
    config: WebAuthnConfig,
}

impl NativeMessagingHost {
    /// Create a new native messaging host
    pub fn new(config: WebAuthnConfig) -> Self {
        Self { config }
    }
    
    /// Run the native messaging host
    pub async fn run(&self) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        
        let mut stdin = stdin;
        let mut stdout = stdout;
        
        loop {
            // Read message length (4 bytes)
            let mut len_bytes = [0u8; 4];
            if let Err(e) = stdin.read_exact(&mut len_bytes).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // Browser disconnected
                    break;
                }
                return Err(crate::Error::Internal(format!("Failed to read length: {}", e)));
            }
            
            let len = u32::from_ne_bytes(len_bytes) as usize;
            
            // Read message body
            let mut message_bytes = vec![0u8; len];
            stdin.read_exact(&mut message_bytes).await
                .map_err(|e| crate::Error::Internal(format!("Failed to read message: {}", e)))?;
            
            // Parse message
            let message: NativeMessage = serde_json::from_slice(&message_bytes)
                .map_err(|e| crate::Error::Internal(format!("Failed to parse message: {}", e)))?;
            
            // Process message
            let response = self.process_message(message).await?;
            
            // Send response
            let response_bytes = serde_json::to_vec(&response)
                .map_err(|e| crate::Error::Internal(format!("Failed to serialize response: {}", e)))?;
            
            let response_len = response_bytes.len() as u32;
            stdout.write_all(&response_len.to_ne_bytes()).await
                .map_err(|e| crate::Error::Internal(format!("Failed to write length: {}", e)))?;
            stdout.write_all(&response_bytes).await
                .map_err(|e| crate::Error::Internal(format!("Failed to write message: {}", e)))?;
            stdout.flush().await
                .map_err(|e| crate::Error::Internal(format!("Failed to flush: {}", e)))?;
        }
        
        Ok(())
    }
    
    /// Process a native message
    async fn process_message(
        &self,
        message: NativeMessage,
    ) -> Result<NativeMessage> {
        match message {
            NativeMessage::Ping => Ok(NativeMessage::Pong),
            NativeMessage::Ctap2Request { id, data } => {
                // Parse CTAP2 request from base64/CBOR
                let _ctap_request = self.parse_ctap2_request(&data)?;
                
                // TODO: Process CTAP2 request
                let response = NativeMessage::Ctap2Response {
                    id,
                    data: "TODO: response".to_string(),
                    error: None,
                };
                
                Ok(response)
            }
            _ => Ok(NativeMessage::Error {
                message: "Unexpected message type".to_string(),
                code: Some(1),
            }),
        }
    }
    
    /// Parse CTAP2 request from base64/CBOR
    fn parse_ctap2_request(&self,
        _data: &str,
    ) -> Result<Ctap2Request> {
        // TODO: Parse base64 and CBOR
        todo!("Implement CTAP2 request parsing")
    }
}

/// Run the native messaging host (entry point)
pub async fn run_host(config: &WebAuthnConfig) -> Result<()> {
    let host = NativeMessagingHost::new(config.clone());
    host.run().await
}

/// Install the native messaging host manifest
pub fn install_manifest() -> Result<()> {
    // TODO: Install host manifest for Chrome/Firefox
    todo!("Implement manifest installation")
}

/// Uninstall the native messaging host manifest
pub fn uninstall_manifest() -> Result<()> {
    // TODO: Remove host manifest
    todo!("Implement manifest uninstallation")
}
