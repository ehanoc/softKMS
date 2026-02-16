//! Test utilities for E2E tests - RAII wrapper for daemon process

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;

static NEXT_PORT: AtomicU16 = AtomicU16::new(51000);

fn find_available_port() -> u16 {
    // Simple approach: try ports from 51000 upward
    for port in (51000..52000).rev() {
        if TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok() {
            return port;
        }
    }
    // Fallback to random
    0
}

/// RAII wrapper for softKMS daemon process
pub struct ServerGuard {
    child: Child,
    port: u16,
    temp_dir: TempDir,
}

impl ServerGuard {
    /// Start a new daemon with a dedicated port
    pub fn new() -> std::io::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let storage_path = temp_dir.path().join("storage");
        let pid_path = temp_dir.path().join("softkms.pid");
        std::fs::create_dir_all(&storage_path)?;

        // Find an available port
        let port = find_available_port();

        // Start daemon
        let mut child = Command::new("target/debug/softkms-daemon")
            .args(&[
                "--storage-path",
                storage_path.to_str().unwrap(),
                "--grpc-addr",
                &format!("127.0.0.1:{}", port),
                "--pid-file",
                pid_path.to_str().unwrap(),
                "--foreground",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Wait for daemon to be ready
        let mut ready = false;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));

            // Check if process is still running
            if let Some(status) = child.try_wait()? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Daemon exited early with status: {:?}", status),
                ));
            }

            // Try TCP connection
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                ready = true;
                break;
            }
        }

        if !ready {
            let _ = child.kill();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timeout waiting for daemon to start",
            ));
        }

        // Give the gRPC server a moment to be fully ready
        std::thread::sleep(Duration::from_secs(2));

        Ok(Self {
            child,
            port,
            temp_dir,
        })
    }

    /// Get the port the daemon is listening on
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the full gRPC address
    pub fn grpc_addr(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Wait for daemon to be ready
    pub fn wait_ready(&self, timeout_secs: u64) -> bool {
        let start = std::time::Instant::now();
        let addr = self.grpc_addr();

        while start.elapsed().as_secs() < timeout_secs {
            let output = Command::new("target/debug/softkms")
                .args(&["--server", &addr, "list"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    return true;
                }
            }

            std::thread::sleep(Duration::from_millis(200));
        }

        false
    }

    /// Initialize the daemon with a passphrase
    pub fn init(&self, passphrase: &str) -> std::io::Result<()> {
        let output = Command::new("target/debug/softkms")
            .args(&[
                "--server",
                &self.grpc_addr(),
                "-p",
                passphrase,
                "init",
                "--confirm",
                "false",
            ])
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Init failed: {}", String::from_utf8_lossy(&output.stderr)),
            ));
        }

        // Give daemon time to fully initialize
        std::thread::sleep(Duration::from_secs(2));

        // Verify daemon is still working
        if !self.wait_ready(10) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Daemon not ready after init",
            ));
        }

        Ok(())
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        // Send SIGTERM for graceful shutdown
        let _ = self.child.kill();

        // Wait for process to exit
        let _ = self.child.wait();

        // Give OS time to release the port
        std::thread::sleep(Duration::from_millis(100));
    }
}
