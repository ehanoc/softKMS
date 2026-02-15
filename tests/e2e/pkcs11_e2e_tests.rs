//! End-to-end tests for PKCS#11 module
//!
//! These tests verify the full workflow: daemon + PKCS#11 + key operations.

use std::process::{Command, Stdio};
use std::time::Duration;

fn setup() {
    // Force kill ALL daemon processes with extreme prejudice
    let _ = Command::new("pkill")
        .args(&["-9", "-f", "softkms-daemon"])
        .output();
    std::thread::sleep(Duration::from_secs(3));

    // Clean data directories
    let _ = std::fs::remove_dir_all("/home/user/.softKMS");
    let _ = std::fs::remove_dir_all("/home/user/.local/share/softKMS");

    // Verify nothing is running on the port
    let _ = Command::new("fuser").args(&["-k", "50051/tcp"]).output();
    std::thread::sleep(Duration::from_secs(1));
}

fn wait_for_daemon_ready() -> bool {
    for i in 0..10 {
        let output = Command::new("./target/debug/softkms")
            .args(&["list"])
            .output();

        if output.map(|o| o.status.success()).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

fn start_fresh_daemon() {
    // Start daemon - fail if can't
    let child = Command::new("./target/debug/softkms-daemon")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start daemon");

    // Don't drop child immediately - let it run
    std::thread::sleep(Duration::from_secs(3));

    // Wait for daemon to be ready
    if !wait_for_daemon_ready() {
        panic!("Daemon did not become ready in time");
    }

    // Initialize with passphrase
    let output = Command::new("./target/debug/softkms")
        .args(&["-p", "test", "init", "--confirm", "false"])
        .output()
        .expect("Failed to run init");

    // CRITICAL: Check init actually worked
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("Init failed: {}", stderr);
    }

    // Give daemon time to fully initialize after init
    std::thread::sleep(Duration::from_secs(1));

    // Verify daemon is still working
    if !wait_for_daemon_ready() {
        panic!("Daemon stopped responding after init");
    }
}

fn teardown() {
    let _ = Command::new("pkill")
        .args(&["-9", "softkms-daemon"])
        .output();
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
fn test_pkcs11_e2e_keygen() {
    setup();
    start_fresh_daemon();

    // Debug: verify daemon is ready
    let ready_check = Command::new("./target/debug/softkms")
        .args(&["-p", "test", "list"])
        .output();

    let ready_ok = ready_check
        .as_ref()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ready_ok {
        eprintln!("WARNING: Daemon might not be ready");
    } else {
        eprintln!("Daemon is ready");
    }

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
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);

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
fn test_pkcs11_e2e_sign() {
    setup();
    start_fresh_daemon();

    // Generate key
    let gen_output = Command::new("pkcs11-tool")
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
        .output()
        .expect("Failed to generate key");

    let gen_stderr = String::from_utf8_lossy(&gen_output.stderr);
    assert!(
        gen_output.status.success(),
        "Key generation failed: {}",
        gen_stderr
    );

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

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "Key {} generation should succeed: {}",
            i,
            stderr
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
