//! Integration tests for REST API
//!
//! These tests verify the REST API endpoints work correctly.
//!
//! Run with: cargo test --test rest_tests
//! Note: These tests run sequentially due to port conflicts

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

static mut CURRENT_PORT: u16 = 62000;

fn find_available_port() -> u16 {
    loop {
        let port = unsafe {
            CURRENT_PORT += 1;
            CURRENT_PORT
        };
        if TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok() {
            return port;
        }
    }
}

struct RestTestServer {
    _temp_dir: TempDir,
    grpc_port: u16,
    rest_port: u16,
    child: std::process::Child,
}

impl RestTestServer {
    fn new() -> std::io::Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        let storage_path = temp_dir.path().join("storage");
        std::fs::create_dir_all(&storage_path)?;

        let grpc_port = find_available_port();
        let rest_port = find_available_port();

        let mut child = Command::new("target/release/softkms-daemon")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(&[
                "--storage-path",
                storage_path.to_str().unwrap(),
                "--grpc-addr",
                &format!("127.0.0.1:{}", grpc_port),
                "--rest-addr",
                &format!("127.0.0.1:{}", rest_port),
                "--foreground",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Wait for REST server to be ready
        let mut ready = false;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if let Ok(Some(status)) = child.try_wait() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Daemon exited early with status: {:?}", status),
                ));
            }
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", rest_port)).is_ok() {
                ready = true;
                break;
            }
        }

        if !ready {
            let _ = child.kill();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timeout waiting for REST server",
            ));
        }

        // Give extra time for gRPC to be ready
        std::thread::sleep(Duration::from_secs(2));

        Ok(Self {
            _temp_dir: temp_dir,
            grpc_port,
            rest_port,
            child,
        })
    }

    fn rest_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rest_port)
    }

    fn grpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.grpc_port)
    }

    fn init(&self, passphrase: &str) -> std::io::Result<()> {
        std::thread::sleep(Duration::from_secs(2));

        let output = Command::new("target/release/softkms")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(&[
                "--server",
                &self.grpc_url(),
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

        std::thread::sleep(Duration::from_secs(3));
        Ok(())
    }

    fn create_identity(
        &self,
        passphrase: &str,
        identity_type: &str,
        description: &str,
    ) -> std::io::Result<(String, String)> {
        let output = Command::new("target/release/softkms")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(&[
                "--server",
                &self.grpc_url(),
                "-p",
                passphrase,
                "identity",
                "create",
                "--type",
                identity_type,
                "--description",
                description,
            ])
            .output()?;

        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Identity create failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        // Parse token - need to handle possible whitespace formatting in output
        let token = stdout
            .lines()
            .find(|l| l.contains("Token:"))
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("")
            .to_string();

        let pubkey = stdout
            .lines()
            .find(|l| l.contains("Public Key:"))
            .and_then(|l| l.split_whitespace().last())
            .unwrap_or("")
            .to_string();

        Ok((token, pubkey))
    }
}

impl Drop for RestTestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http_get(url: &str) -> reqwest::blocking::Response {
    reqwest::blocking::get(url).expect("HTTP request failed")
}

fn http_get_with_auth(url: &str, token: &str) -> reqwest::blocking::Response {
    let client = reqwest::blocking::Client::new();
    client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .expect("HTTP request failed")
}

fn run_tests() -> Result<(), String> {
    println!("Running REST API tests...");

    // Test 1: Health endpoint
    println!("  Test: health endpoint...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    let response = http_get(&format!("{}/health", server.rest_url()));
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().unwrap(), "OK");
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 2: Status endpoint
    println!("  Test: status endpoint...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    let response = http_get(&format!("{}/v1/status", server.rest_url()));
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
    assert!(body.get("version").is_some());
    assert!(body.get("grpc_addr").is_some());
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 3: List keys without auth
    println!("  Test: list keys without auth...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    let response = http_get(&format!("{}/v1/keys", server.rest_url()));
    assert_eq!(response.status(), 401);
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 4: List keys with auth
    println!("  Test: list keys with auth...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    server.init("test-passphrase").map_err(|e| e.to_string())?;
    let (token, _pubkey) = server
        .create_identity("test-passphrase", "ai-agent", "Test")
        .map_err(|e| e.to_string())?;
    let response = http_get_with_auth(&format!("{}/v1/keys", server.rest_url()), &token);
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
    assert!(body.get("keys").is_some());
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 5: Create key
    println!("  Test: create key...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    server.init("test-passphrase").map_err(|e| e.to_string())?;
    let (token, _pubkey) = server
        .create_identity("test-passphrase", "ai-agent", "Test")
        .map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "algorithm": "ed25519",
        "label": "test-key"
    });
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(&format!("{}/v1/keys", server.rest_url()))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .expect("HTTP request failed");
    assert_eq!(response.status(), 200);
    let result: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
    assert!(result.get("key_id").is_some());
    assert_eq!(result.get("algorithm").unwrap(), "ed25519");
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 6: Sign
    println!("  Test: sign...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    server.init("test-passphrase").map_err(|e| e.to_string())?;
    let (token, _pubkey) = server
        .create_identity("test-passphrase", "ai-agent", "Test")
        .map_err(|e| e.to_string())?;
    let create_body = serde_json::json!({
        "algorithm": "ed25519",
        "label": "signing-key"
    });
    let client = reqwest::blocking::Client::new();
    let create_response = client
        .post(&format!("{}/v1/keys", server.rest_url()))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(create_body.to_string())
        .send()
        .expect("HTTP request failed");
    let create_result: serde_json::Value =
        serde_json::from_str(&create_response.text().unwrap()).unwrap();
    let key_id = create_result.get("key_id").unwrap().as_str().unwrap();
    use base64::Engine as _;
    let data = base64::engine::general_purpose::STANDARD.encode(b"test data to sign");
    let sign_body = serde_json::json!({
        "data": data
    });
    let sign_response = client
        .post(&format!("{}/v1/keys/{}/sign", server.rest_url(), key_id))
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(sign_body.to_string())
        .send()
        .expect("HTTP request failed");
    assert_eq!(sign_response.status(), 200);
    let sign_result: serde_json::Value =
        serde_json::from_str(&sign_response.text().unwrap()).unwrap();
    assert!(sign_result.get("signature").is_some());
    assert!(sign_result.get("algorithm").is_some());
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 7: Get identity
    println!("  Test: get identity...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    server.init("test-passphrase").map_err(|e| e.to_string())?;
    let (token, pubkey) = server
        .create_identity("test-passphrase", "ai-agent", "My Test Identity")
        .map_err(|e| e.to_string())?;
    let response = http_get_with_auth(&format!("{}/v1/identities/me", server.rest_url()), &token);
    assert_eq!(response.status(), 200);
    let result: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
    assert_eq!(result.get("public_key").unwrap(), &pubkey);
    assert_eq!(result.get("client_type").unwrap(), "ai-agent");
    assert_eq!(result.get("description").unwrap(), "My Test Identity");
    assert_eq!(result.get("is_active").unwrap(), true);
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 8: Invalid token
    println!("  Test: invalid token...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    server.init("test-passphrase").map_err(|e| e.to_string())?;
    let response = http_get_with_auth(&format!("{}/v1/keys", server.rest_url()), "invalid-token");
    assert_eq!(response.status(), 401);
    drop(server);
    std::thread::sleep(Duration::from_millis(500));

    // Test 9: x-softkms-token header
    println!("  Test: x-softkms-token header...");
    let server = RestTestServer::new().map_err(|e| e.to_string())?;
    server.init("test-passphrase").map_err(|e| e.to_string())?;
    let (token, _pubkey) = server
        .create_identity("test-passphrase", "service", "Test Service")
        .map_err(|e| e.to_string())?;
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(&format!("{}/v1/keys", server.rest_url()))
        .header("x-softkms-token", &token)
        .send()
        .expect("HTTP request failed");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&response.text().unwrap()).unwrap();
    assert!(body.get("keys").is_some());
    drop(server);

    println!("All REST API tests passed!");
    Ok(())
}

#[tokio::test]
async fn test_falcon512_key_creation_via_rest() {
    let (service, _temp) = setup_test_env().await;
    let passphrase = "test_passphrase";

    let metadata = service.create_key(
        "falcon512".to_string(),
        Some("Falcon512 Key".to_string()),
        std::collections::HashMap::new(),
        passphrase,
        None,
    ).await.unwrap();

    assert_eq!(metadata.algorithm, "falcon512");
    assert_eq!(metadata.public_key.len(), 897);
}

fn main() {
    if let Err(e) = run_tests() {
        eprintln!("REST tests failed: {}", e);
        std::process::exit(1);
    }
}
