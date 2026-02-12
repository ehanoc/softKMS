//! IPC module - Inter-process communication

/// IPC types and traits
pub trait IpcChannel {
    fn send(&self, data: &[u8]) -> impl std::future::Future<Output = crate::Result<()>> + Send;
    fn receive(&self) -> impl std::future::Future<Output = crate::Result<Vec<u8>>> + Send;
}
