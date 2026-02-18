//! Test utilities for E2E tests - RAII wrapper for daemon process

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;

static NEXT_PORT: AtomicU16 = AtomicU16::new(51000);

fn find_available_port() -> u16 {
    // Atomic counter to avoid port conflicts between parallel tests
    for _ in 0..200 {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let effective_port = if port >= 52000 {
            // Wrap around to avoid running out of ports
            51000 + (port - 52000)
        } else {
            port
        };

        if TcpListener::bind(format!("127.0.0.1:{}", effective_port)).is_ok() {
            return effective_port;
        }
    }
    // Fallback: let the OS assign a random available port
    if let Ok(listener) = TcpListener::bind("127.0.0.1:0") {
        if let Ok(addr) = listener.local_addr() {
            return addr.port();
        }
    }
    // Last resort
    51000
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

        // Start daemon (use release build for tests)
        let mut child = Command::new("target/release/softkms-daemon")
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
                .args(&["--server", &addr, "health"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    return true;
                }
                eprintln!(
                    "Health check failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                eprintln!("Health check error: {:?}", output.err());
            }

            std::thread::sleep(Duration::from_millis(500));
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
        std::thread::sleep(Duration::from_secs(4));

        // Verify daemon is still working with retries
        let mut retries = 5;
        while retries > 0 {
            if self.wait_ready(10) {
                return Ok(());
            }
            retries -= 1;
            if retries > 0 {
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Daemon not ready after init",
        ))
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
