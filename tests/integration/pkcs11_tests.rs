//! Integration tests for PKCS#11 module with daemon
//!
//! These tests require the softKMS daemon to be running and initialized.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

/// Helper to start the daemon
fn start_daemon() {
    // Kill any existing daemon
    let _ = Command::new("pkill").arg("softkms-daemon").output();
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Start daemon in background
    let mut daemon = Command::new("cargo")
        .args(&["run", "--bin", "softkms-daemon"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start daemon");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Check if daemon is running
    let output = Command::new("pgrep")
        .arg("-a")
        .arg("softkms-daemon")
        .output()
        .expect("Failed to check daemon");

    if !output.status.success() {
        panic!("Daemon failed to start");
    }
}

/// Helper to initialize the keystore
fn init_keystore(passphrase: &str) {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "softkms",
            "--",
            "-p",
            passphrase,
            "init",
            "--confirm",
            "false",
        ])
        .output()
        .expect("Failed to init keystore");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "already initialized" errors
        if !stderr.contains("already initialized") && !stderr.contains("Keystore already") {
            panic!("Failed to init keystore: {}", stderr);
        }
    }
}

/// Helper to cleanup
fn cleanup() {
    let _ = Command::new("pkill").arg("softkms-daemon").output();
    let _ = fs::remove_dir_all("/home/user/.softKMS");
    let _ = fs::remove_dir_all("/home/user/.local/share/softKMS");
}

#[test]
#[ignore] // Requires daemon to be built and runnable
fn test_pkcs11_module_loads() {
    cleanup();
    start_daemon();
    init_keystore("test123");

    // Test that the module loads
    let output = Command::new("pkcs11-tool")
        .args(&["--module", "target/debug/libsoftkms.so", "--list-slots"])
        .output()
        .expect("Failed to run pkcs11-tool");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show at least one slot
    assert!(stdout.contains("Slot"), "Module should list slots");
    assert!(output.status.success(), "pkcs11-tool should succeed");

    cleanup();
}

#[test]
#[ignore] // Requires daemon to be built and runnable
fn test_pkcs11_list_mechanisms() {
    cleanup();
    start_daemon();
    init_keystore("test123");

    // Test listing mechanisms
    let output = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--list-mechanisms",
        ])
        .output()
        .expect("Failed to run pkcs11-tool");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show ECDSA mechanisms
    assert!(stdout.contains("ECDSA"), "Should list ECDSA mechanism");
    assert!(output.status.success(), "pkcs11-tool should succeed");

    cleanup();
}

#[test]
#[ignore] // Requires daemon to be built and runnable
fn test_pkcs11_key_generation() {
    cleanup();
    start_daemon();
    init_keystore("test123");

    // Generate a key
    let output = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test123",
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "test-key",
            "-m",
            "0x1050",
        ])
        .output()
        .expect("Failed to run pkcs11-tool");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should succeed
    assert!(
        output.status.success(),
        "Key generation should succeed: {}",
        stderr
    );
    assert!(
        stdout.contains("Key pair generated"),
        "Should show key generated"
    );

    cleanup();
}

#[test]
#[ignore] // Requires daemon to be built and runnable
fn test_pkcs11_sign_data() {
    cleanup();
    start_daemon();
    init_keystore("test123");

    // First generate a key
    let _ = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test123",
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "test-sign-key",
            "-m",
            "0x1050",
        ])
        .output();

    // Create test data file
    let mut temp_file = std::env::temp_dir().join("pkcs11_test_data.txt");
    fs::write(&temp_file, "Hello World").unwrap();

    // Sign data
    let output = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test123",
            "--sign",
            "--label",
            "test-sign-key",
            "--input-file",
            temp_file.to_str().unwrap(),
            "--output-file",
            "/tmp/test_signature.bin",
            "-m",
            "0x1001",
        ])
        .output()
        .expect("Failed to run pkcs11-tool");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("stdout: {}", stdout);
    println!("stderr: {}", stderr);

    // Should succeed
    assert!(
        output.status.success(),
        "Signing should succeed: {}",
        stderr
    );

    // Cleanup
    let _ = fs::remove_file(temp_file);
    let _ = fs::remove_file("/tmp/test_signature.bin");
    cleanup();
}

#[test]
#[ignore] // Requires daemon to be built and runnable
fn test_pkcs11_daemon_keys_persist() {
    cleanup();
    start_daemon();
    init_keystore("test123");

    // Generate a key
    let _ = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test123",
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "persistent-key",
            "-m",
            "0x1050",
        ])
        .output();

    // Kill and restart daemon
    let _ = Command::new("pkill").arg("softkms-daemon").output();
    std::thread::sleep(std::time::Duration::from_secs(1));
    start_daemon();

    // Check keys persist
    let output = Command::new("cargo")
        .args(&["run", "--bin", "softkms", "--", "-p", "test", "list"])
        .output()
        .expect("Failed to list keys");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show the key we created
    assert!(
        stdout.contains("persistent-key") || stdout.contains("pkcs11-key"),
        "Key should persist across daemon restarts"
    );

    cleanup();
}
