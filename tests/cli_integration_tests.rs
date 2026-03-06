//! Integration tests for CLI commands
//!
//! These tests verify CLI functionality works end-to-end.
//! Note: These tests run serially to avoid port conflicts.

use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use tempfile::TempDir;

// Global lock to ensure tests run serially
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Test helper to start daemon and run CLI
struct CliTest {
    temp_dir: TempDir,
    daemon_process: Option<std::process::Child>,
    port: u16,
}

impl CliTest {
    fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        // Generate random port between 10000-60000 to avoid conflicts
        let port = 10000
            + (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % 50000) as u16;
        Self {
            temp_dir,
            daemon_process: None,
            port,
        }
    }

    fn start_daemon(&mut self) {
        let storage_path = self.temp_dir.path().to_path_buf();
        let pid_file = self.temp_dir.path().join("softkms.pid");

        // Use debug binary if running tests, otherwise release
        let daemon_path = if cfg!(debug_assertions) {
            "./target/debug/softkms-daemon"
        } else {
            "./target/release/softkms-daemon"
        };

        // Start daemon with custom storage path and random port
        let grpc_addr = format!("127.0.0.1:{}", self.port);
        let daemon = Command::new(daemon_path)
            .arg("--storage-path")
            .arg(&storage_path)
            .arg("--grpc-addr")
            .arg(&grpc_addr)
            .arg("--pid-file")
            .arg(&pid_file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Failed to start daemon");

        self.daemon_process = Some(daemon);

        // Wait for daemon to start
        std::thread::sleep(Duration::from_millis(500));
    }

    fn run_cli(&self, args: &[&str]) -> std::process::Output {
        // Use debug binary if running tests, otherwise release
        let cli_path = if cfg!(debug_assertions) {
            "./target/debug/softkms"
        } else {
            "./target/release/softkms"
        };
        let server_addr = format!("http://127.0.0.1:{}", self.port);
        Command::new(cli_path)
            .arg("--server")
            .arg(&server_addr)
            .args(args)
            .output()
            .expect("Failed to run CLI")
    }
}

impl Drop for CliTest {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon_process.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}

#[test]
fn test_cli_p256_key_generation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    let init_output = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);
    let init_stdout = String::from_utf8_lossy(&init_output.stdout);
    let init_stderr = String::from_utf8_lossy(&init_output.stderr);

    println!("Init stdout: {}", init_stdout);
    println!("Init stderr: {}", init_stderr);

    let output = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "p256",
        "--label",
        "TestP256Key",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Generate stdout: {}", stdout);
    println!("Generate stderr: {}", stderr);
    println!("Exit code: {}", output.status.code().unwrap_or(-1));

    assert!(
        output.status.success(),
        "P-256 key generation failed: stdout={}, stderr={}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("Key generated successfully"),
        "Expected success message"
    );
    assert!(
        stdout.contains("Algorithm: p256"),
        "Expected p256 algorithm"
    );
}

#[test]
fn test_cli_p256_sign_and_verify() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    let _ = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);

    let gen_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "p256",
        "--label",
        "SignVerifyKey",
    ]);

    let gen_stdout = String::from_utf8_lossy(&gen_output.stdout);
    assert!(gen_output.status.success(), "Key generation failed");

    // Extract key ID for verify
    let key_id = gen_stdout
        .lines()
        .find(|l| l.starts_with("  ID:"))
        .expect("No key ID in output")
        .split(":")
        .nth(1)
        .expect("Could not extract key ID")
        .trim()
        .to_string();

    let sign_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "sign",
        "--label",
        "SignVerifyKey",
        "--data",
        "Hello, World!",
    ]);

    let sign_stdout = String::from_utf8_lossy(&sign_output.stdout);
    println!("Sign stdout: {}", sign_stdout);

    assert!(
        sign_output.status.success(),
        "Signing failed: {}",
        sign_stdout
    );
    assert!(
        sign_stdout.contains("Signature (base64):"),
        "Expected signature output"
    );

    let signature_line = sign_stdout
        .lines()
        .find(|l| l.contains("Signature (base64):"))
        .expect("No signature in output");

    let signature = signature_line
        .split("Signature (base64):")
        .nth(1)
        .expect("Could not extract signature")
        .trim();

    let verify_output = test.run_cli(&[
        "verify",
        "--key",
        &key_id,
        "--data",
        "Hello, World!",
        "--signature",
        signature,
    ]);

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    let verify_stderr = String::from_utf8_lossy(&verify_output.stderr);

    println!("Verify stdout: {}", verify_stdout);
    println!("Verify stderr: {}", verify_stderr);

    assert!(
        verify_output.status.success(),
        "Verification failed: {}",
        verify_stderr
    );
    assert!(
        verify_stdout.contains("VALID"),
        "Expected signature to be valid"
    );
}

#[test]
fn test_cli_ed25519_sign_and_verify() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    let _ = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);

    let gen_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "ed25519",
        "--label",
        "Ed25519SignKey",
    ]);

    let gen_stdout = String::from_utf8_lossy(&gen_output.stdout);
    let gen_stderr = String::from_utf8_lossy(&gen_output.stderr);
    println!("Ed25519 gen stdout: {}", gen_stdout);
    println!("Ed25519 gen stderr: {}", gen_stderr);
    assert!(
        gen_output.status.success(),
        "Ed25519 key generation failed: {}",
        gen_stderr
    );

    let sign_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "sign",
        "--label",
        "Ed25519SignKey",
        "--data",
        "Test message for Ed25519",
    ]);

    let sign_stdout = String::from_utf8_lossy(&sign_output.stdout);
    assert!(
        sign_output.status.success(),
        "Ed25519 signing failed: {}",
        sign_stdout
    );

    // Extract key ID for verify
    let key_id = gen_stdout
        .lines()
        .find(|l| l.starts_with("  ID:"))
        .expect("No key ID in output")
        .split(":")
        .nth(1)
        .expect("Could not extract key ID")
        .trim()
        .to_string();

    let signature_line = sign_stdout
        .lines()
        .find(|l| l.contains("Signature (base64):"))
        .expect("No signature in output");

    let signature = signature_line
        .split("Signature (base64):")
        .nth(1)
        .expect("Could not extract signature")
        .trim();

    let verify_output = test.run_cli(&[
        "verify",
        "--key",
        &key_id,
        "--data",
        "Test message for Ed25519",
        "--signature",
        signature,
    ]);

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(
        verify_output.status.success(),
        "Ed25519 verification failed"
    );
    assert!(
        verify_stdout.contains("VALID"),
        "Expected Ed25519 signature to be valid"
    );
    assert!(
        verify_stdout.contains("ed25519"),
        "Expected ed25519 algorithm"
    );
}

#[test]
fn test_cli_verify_invalid_signature() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    let _ = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);

    let gen_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "p256",
        "--label",
        "InvalidSigKey",
    ]);

    let gen_stdout = String::from_utf8_lossy(&gen_output.stdout);

    // Extract key ID for verify
    let key_id = gen_stdout
        .lines()
        .find(|l| l.starts_with("  ID:"))
        .expect("No key ID in output")
        .split(":")
        .nth(1)
        .expect("Could not extract key ID")
        .trim()
        .to_string();

    let sign_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "sign",
        "--label",
        "InvalidSigKey",
        "--data",
        "Original data",
    ]);

    let sign_stdout = String::from_utf8_lossy(&sign_output.stdout);
    let signature_line = sign_stdout
        .lines()
        .find(|l| l.contains("Signature (base64):"))
        .unwrap();

    let signature = signature_line
        .split("Signature (base64):")
        .nth(1)
        .unwrap()
        .trim();

    let verify_output = test.run_cli(&[
        "verify",
        "--key",
        &key_id,
        "--data",
        "Different data",
        "--signature",
        signature,
    ]);

    assert!(
        !verify_output.status.success(),
        "Verification should fail for wrong data"
    );

    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(
        verify_stdout.contains("INVALID"),
        "Expected signature to be invalid"
    );
}

#[test]
fn test_cli_ed25519_key_generation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    let _ = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);

    let output = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "ed25519",
        "--label",
        "TestEd25519Key",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("Ed25519 stdout: {}", stdout);
    println!("Ed25519 stderr: {}", stderr);

    assert!(output.status.success(), "Ed25519 key generation failed");
    assert!(
        stdout.contains("Algorithm: ed25519"),
        "Expected ed25519 algorithm"
    );
}

#[test]
fn test_cli_list_keys() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    let _ = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);

    let _ = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "p256",
        "--label",
        "Key1",
    ]);

    let _ = test.run_cli(&[
        "--passphrase",
        "test123",
        "generate",
        "--algorithm",
        "ed25519",
        "--label",
        "Key2",
    ]);

    let list_output = test.run_cli(&["--passphrase", "test123", "list"]);
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);

    println!("List stdout: {}", list_stdout);

    assert!(list_output.status.success(), "List failed");
    assert!(list_stdout.contains("Key1"), "Expected Key1 in list");
    assert!(list_stdout.contains("Key2"), "Expected Key2 in list");
    assert!(list_stdout.contains("Total: 2 keys"), "Expected 2 keys");
}

#[test]
fn test_cli_derive_seed_by_label() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut test = CliTest::new();
    test.start_daemon();

    std::thread::sleep(Duration::from_millis(1000));

    // Initialize the keystore
    let _ = test.run_cli(&["--passphrase", "test123", "init", "--confirm", "false"]);

    // Import a seed with a label
    let seed_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "import-seed",
        "--mnemonic",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "--label",
        "test-seed-label",
    ]);

    let seed_stdout = String::from_utf8_lossy(&seed_output.stdout);
    println!("Seed import stdout: {}", seed_stdout);
    assert!(seed_output.status.success(), "Seed import failed");

    // Extract the seed ID from output
    let seed_id = seed_stdout
        .lines()
        .find(|line| line.contains("Seed ID:"))
        .and_then(|line| line.split("Seed ID:").nth(1))
        .map(|s| s.trim().to_string())
        .expect("Should have seed ID in output");

    println!("Seed ID: {}", seed_id);

    // Derive Ed25519 key using the LABEL instead of UUID
    let derive_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "derive",
        "--algorithm",
        "ed25519",
        "--seed",
        "test-seed-label", // Use label instead of UUID
        "--path",
        "m/44'/283'/0'/0/0",
        "--label",
        "derived-by-label",
    ]);

    let derive_stdout = String::from_utf8_lossy(&derive_output.stdout);
    let derive_stderr = String::from_utf8_lossy(&derive_output.stderr);

    println!("Derive stdout: {}", derive_stdout);
    println!("Derive stderr: {}", derive_stderr);

    assert!(
        derive_output.status.success(),
        "Derive with label failed: {}",
        derive_stderr
    );
    assert!(
        derive_stdout.contains("Ed25519 key derived successfully"),
        "Expected successful derivation message"
    );
    // Note: The derive command doesn't output the label, it only stores it
    // The key was successfully derived using the seed label

    // Also test P-256 derivation with label
    let p256_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "derive",
        "--algorithm",
        "p256",
        "--seed",
        "test-seed-label", // Use label instead of UUID
        "--origin",
        "example.com",
        "--user-handle",
        "user@example.com",
        "--counter",
        "0",
        "--label",
        "p256-by-label",
    ]);

    let p256_stdout = String::from_utf8_lossy(&p256_output.stdout);
    let p256_stderr = String::from_utf8_lossy(&p256_output.stderr);

    println!("P-256 derive stdout: {}", p256_stdout);
    println!("P-256 derive stderr: {}", p256_stderr);

    assert!(
        p256_output.status.success(),
        "P-256 derive with label failed: {}",
        p256_stderr
    );
    assert!(
        p256_stdout.contains("P-256 key derived successfully"),
        "Expected successful P-256 derivation message"
    );

    // Test error case: non-existent label
    let fail_output = test.run_cli(&[
        "--passphrase",
        "test123",
        "derive",
        "--algorithm",
        "ed25519",
        "--seed",
        "non-existent-seed-label",
        "--path",
        "m/44'/283'/0'/0/0",
    ]);

    let fail_stderr = String::from_utf8_lossy(&fail_output.stderr);
    println!("Expected failure stderr: {}", fail_stderr);

    assert!(
        !fail_output.status.success(),
        "Should fail with non-existent label"
    );
    assert!(
        fail_stderr.contains("No seed found with label"),
        "Expected seed not found error, got: {}",
        fail_stderr
    );
}
