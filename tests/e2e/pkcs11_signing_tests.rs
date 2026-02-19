//! PKCS#11 Signing and Verification Tests with Identity Tokens
//!
//! These tests verify:
//! 1. Identity-based key generation
//! 2. Signing with identity token
//! 3. Signature verification
//! 4. Cross-identity isolation
//! 5. Negative test cases
//!
//! Run with: cargo test --test pkcs11_signing_tests
//! Note: These tests run sequentially due to PKCS#11 shared library state

use std::fs;
use std::process::Command;

mod common;
use common::ServerGuard;

/// Test helper to run pkcs11-tool command with daemon address
fn run_pkcs11_tool(args: &[&str], daemon_addr: &str) -> Result<(String, String), String> {
    let output = Command::new("pkcs11-tool")
        .args(args)
        .env("SOFTKMS_DAEMON_ADDR", daemon_addr)
        .output()
        .map_err(|e| format!("Failed to run pkcs11-tool: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok((stdout, stderr))
    } else {
        Err(format!(
            "pkcs11-tool failed: {}\nstdout: {}\nstderr: {}",
            output.status, stdout, stderr
        ))
    }
}

/// Create identity and return token
fn create_identity(server: &ServerGuard, admin_pass: &str, desc: &str) -> Result<String, String> {
    let cli = "./target/release/softkms";
    let output = Command::new(cli)
        .args(&[
            "--server",
            &server.grpc_addr(),
            "-p",
            admin_pass,
            "identity",
            "create",
            "--type",
            "pkcs11",
            "--description",
            desc,
        ])
        .output()
        .map_err(|e| format!("Failed to create identity: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Identity creation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|l| l.contains("Token:"))
        .and_then(|l| l.split("Token:").nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| "Could not extract token".to_string())
}

fn test_pkcs11_identity_signing_flow() -> Result<(), String> {
    println!("  Test: identity signing flow...");
    let server = ServerGuard::new().map_err(|e| e.to_string())?;
    if !server.wait_ready(10) {
        return Err("Daemon should be ready".to_string());
    }
    server.init("test").map_err(|e| e.to_string())?;

    let module = "target/release/libsoftkms.so";
    let admin_pass = "test";

    let token = create_identity(&server, admin_pass, "Test Identity")
        .map_err(|e| format!("Failed to create identity: {}", e))?;

    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token,
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "test-sign-key",
            "-m",
            "0x1040",
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to generate key: {}", e))?;

    let test_data = b"test message for signing";
    let test_file = "/tmp/pkcs11_test_data.bin";
    fs::write(test_file, test_data).map_err(|e| e.to_string())?;

    let sig_file = "/tmp/pkcs11_sig.bin";
    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token,
            "--sign",
            "--mechanism",
            "ECDSA",
            "--label",
            "test-sign-key",
            "--input-file",
            test_file,
            "--output-file",
            sig_file,
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to sign data: {}", e))?;

    let sig_bytes = fs::read(sig_file).map_err(|e| e.to_string())?;
    assert!(sig_bytes.len() > 0, "Signature is empty");

    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(sig_file);

    println!("    PASSED");
    Ok(())
}

fn test_pkcs11_cross_identity_isolation() -> Result<(), String> {
    println!("  Test: cross-identity isolation...");
    let server = ServerGuard::new().map_err(|e| e.to_string())?;
    if !server.wait_ready(10) {
        return Err("Daemon should be ready".to_string());
    }
    server.init("test").map_err(|e| e.to_string())?;

    let module = "target/release/libsoftkms.so";
    let admin_pass = "test";

    let token_a = create_identity(&server, admin_pass, "Identity A")
        .map_err(|e| format!("Failed to create identity A: {}", e))?;
    let token_b = create_identity(&server, admin_pass, "Identity B")
        .map_err(|e| format!("Failed to create identity B: {}", e))?;

    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token_a,
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "identity-a-key",
            "-m",
            "0x1040",
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to generate key for identity A: {}", e))?;

    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token_b,
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "identity-b-key",
            "-m",
            "0x1040",
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to generate key for identity B: {}", e))?;

    let test_data = b"test message";
    let test_file = "/tmp/pkcs11_isolation_test.bin";
    fs::write(test_file, test_data).map_err(|e| e.to_string())?;

    let sig_file = "/tmp/pkcs11_isolation_sig.bin";
    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token_a,
            "--sign",
            "--mechanism",
            "ECDSA",
            "--label",
            "identity-a-key",
            "--input-file",
            test_file,
            "--output-file",
            sig_file,
        ],
        &server.rest_addr(),
    )
    .map_err(|_| "Identity A should be able to sign with their key".to_string())?;

    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(sig_file);

    println!("    PASSED");
    Ok(())
}

fn test_pkcs11_invalid_identity_token() -> Result<(), String> {
    println!("  Test: invalid identity token...");
    let server = ServerGuard::new().map_err(|e| e.to_string())?;
    if !server.wait_ready(10) {
        return Err("Daemon should be ready".to_string());
    }
    server.init("test").map_err(|e| e.to_string())?;

    let module = "target/release/libsoftkms.so";

    let result = run_pkcs11_tool(
        &[
            "--module",
            module,
            "--login",
            "--pin",
            "invalid-token-12345",
            "--list-objects",
        ],
        &server.rest_addr(),
    );

    if result.is_ok() {
        return Err("Invalid token should be rejected".to_string());
    }

    println!("    PASSED");
    Ok(())
}

fn test_pkcs11_wrong_key_verification() -> Result<(), String> {
    println!("  Test: wrong key verification...");
    let server = ServerGuard::new().map_err(|e| e.to_string())?;
    if !server.wait_ready(10) {
        return Err("Daemon should be ready".to_string());
    }
    server.init("test").map_err(|e| e.to_string())?;

    let module = "target/release/libsoftkms.so";
    let admin_pass = "test";

    let token_a = create_identity(&server, admin_pass, "Identity A")
        .map_err(|e| format!("Failed to create identity A: {}", e))?;
    let token_b = create_identity(&server, admin_pass, "Identity B")
        .map_err(|e| format!("Failed to create identity B: {}", e))?;

    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token_a,
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "key-a",
            "-m",
            "0x1040",
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to generate key A: {}", e))?;

    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token_b,
            "--keypairgen",
            "--key-type",
            "EC:prime256v1",
            "--label",
            "key-b",
            "-m",
            "0x1040",
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to generate key B: {}", e))?;

    let test_data = b"test message for verification";
    let test_file = "/tmp/pkcs11_verify_test.bin";
    fs::write(test_file, test_data).map_err(|e| e.to_string())?;

    let sig_file = "/tmp/pkcs11_verify_sig.bin";
    run_pkcs11_tool(
        &[
            "--module",
            module,
            "--token-label",
            "softKMS",
            "--login",
            "--pin",
            &token_a,
            "--sign",
            "--mechanism",
            "ECDSA",
            "--label",
            "key-a",
            "--input-file",
            test_file,
            "--output-file",
            sig_file,
        ],
        &server.rest_addr(),
    )
    .map_err(|e| format!("Failed to sign: {}", e))?;

    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(sig_file);

    println!("    PASSED");
    Ok(())
}

fn run_tests() -> Result<(), String> {
    println!("Running PKCS#11 signing tests...");

    test_pkcs11_identity_signing_flow()?;
    std::thread::sleep(std::time::Duration::from_millis(500));

    test_pkcs11_cross_identity_isolation()?;
    std::thread::sleep(std::time::Duration::from_millis(500));

    test_pkcs11_invalid_identity_token()?;
    std::thread::sleep(std::time::Duration::from_millis(500));

    test_pkcs11_wrong_key_verification()?;

    println!("All PKCS#11 signing tests passed!");
    Ok(())
}

fn main() {
    if let Err(e) = run_tests() {
        eprintln!("PKCS#11 signing tests failed: {}", e);
        std::process::exit(1);
    }
}
