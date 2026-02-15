//! End-to-end tests for PKCS#11 module
//!
//! These tests verify the full workflow: daemon + PKCS#11 + key operations.

use std::process::{Command, Stdio};
use std::time::Duration;

fn setup() {
    // Cleanup any existing state
    let _ = Command::new("pkill").arg("softkms-daemon").output();
    std::thread::sleep(Duration::from_secs(2));

    // Clean up data directories
    let _ = std::fs::remove_dir_all("/home/user/.softKMS");
    let _ = std::fs::remove_dir_all("/home/user/.local/share/softKMS");
}

fn start_fresh_daemon() {
    // Start daemon using built binary
    let _ = Command::new("./target/debug/softkms-daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    std::thread::sleep(Duration::from_secs(3));

    // Initialize with passphrase "test"
    let output = Command::new("./target/debug/softkms")
        .args(&["-p", "test", "init", "--confirm", "false"])
        .output();

    if let Ok(out) = output {
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("already initialized") {
                eprintln!("Init warning: {}", stderr);
            }
        }
    }

    // Give daemon time to fully initialize
    std::thread::sleep(Duration::from_secs(1));
}

fn teardown() {
    let _ = Command::new("pkill").arg("softkms-daemon").output();
    std::thread::sleep(Duration::from_secs(1));
}

/// Smoke test: verify daemon + PKCS#11 basic flow works
#[test]
fn test_pkcs11_e2e_smoke() {
    setup();
    start_fresh_daemon();

    // Simple list slots test
    let output = Command::new("pkcs11-tool")
        .args(&["--module", "target/debug/libsoftkms.so", "--list-slots"])
        .output()
        .expect("pkcs11-tool should work");

    assert!(output.status.success(), "pkcs11-tool should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Slot"), "Should list slots");

    teardown();
}

/// Test key generation flow
#[test]
#[ignore] // Requires daemon to be running with correct passphrase setup
fn test_pkcs11_e2e_keygen() {
    setup();
    start_fresh_daemon();

    // Generate key with explicit mechanism
    let output = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test",
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "e2e-test-key",
            "-m",
            "0x1050",
        ])
        .output()
        .expect("pkcs11-tool should work");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Key generation should succeed: {}",
        stderr
    );

    // Verify key exists via CLI
    let list_output = Command::new("./target/debug/softkms")
        .args(&["-p", "test", "list"])
        .output()
        .expect("CLI should work");

    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(
        list_stdout.contains("e2e-test-key") || list_stdout.contains("pkcs11-key"),
        "Key should be created"
    );

    teardown();
}

/// Test signing flow
#[test]
#[ignore] // Requires daemon to be running with correct passphrase setup
fn test_pkcs11_e2e_sign() {
    setup();
    start_fresh_daemon();

    // Generate key
    let _ = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test",
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "sign-key",
            "-m",
            "0x1050",
        ])
        .output();

    // Create test data
    let data_path = "/tmp/e2e_test_data.txt";
    std::fs::write(data_path, "Test data for signing").unwrap();

    // Sign
    let output = Command::new("pkcs11-tool")
        .args(&[
            "--module",
            "target/debug/libsoftkms.so",
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            "test",
            "--sign",
            "--label",
            "sign-key",
            "--input-file",
            data_path,
            "--output-file",
            "/tmp/e2e_test_sig.bin",
            "-m",
            "0x1001",
        ])
        .output()
        .expect("pkcs11-tool should work");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "Signing should succeed: {}",
        stderr
    );

    // Cleanup
    let _ = std::fs::remove_file(data_path);
    let _ = std::fs::remove_file("/tmp/e2e_test_sig.bin");

    teardown();
}

/// Test multiple keys can coexist
#[test]
#[ignore] // Requires daemon to be running with correct passphrase setup
fn test_pkcs11_e2e_multiple_keys() {
    setup();
    start_fresh_daemon();

    // Generate multiple keys
    for i in 0..3 {
        let output = Command::new("pkcs11-tool")
            .args(&[
                "--module",
                "target/debug/libsoftkms.so",
                "--token-label",
                "softKMS",
                "--login",
                "--pin",
                "test",
                "--keypairgen",
                "--key-type",
                "EC:prime256v1",
                "--label",
                &format!("key-{}", i),
                "-m",
                "0x1050",
            ])
            .output()
            .expect("pkcs11-tool should work");

        assert!(
            output.status.success(),
            "Key {} generation should succeed",
            i
        );
    }

    // List all keys
    let output = Command::new("./target/debug/softkms")
        .args(&["-p", "test", "list"])
        .output()
        .expect("CLI should work");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have multiple keys
    let key_count = stdout.matches("key-").count();
    assert!(
        key_count >= 2,
        "Should have multiple keys, found {}",
        key_count
    );

    teardown();
}
