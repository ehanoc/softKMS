//! End-to-end tests for softKMS
//!
//! These tests verify complete workflows from CLI to daemon.

use std::process::Command;
use std::time::Duration;

/// Test CLI help command
#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "softkms-cli", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run CLI --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // CLI should show usage info
    let combined = format!("{} {}", stdout, stderr);
    assert!(
        combined.contains("softkms-cli")
            || combined.contains("USAGE")
            || combined.contains("Commands"),
        "Expected CLI to show help. Got stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

/// Test daemon and CLI version match
#[test]
fn test_version_match() {
    // This test verifies that daemon and CLI report the same version
    // Once implemented, both should return the same version string

    // For now, just verify the version constant exists
    let version = env!("CARGO_PKG_VERSION");
    assert!(!version.is_empty());

    // Check version format (should be semver)
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "Version should be in semver format");
}

/// Test configuration file loading
#[test]
fn test_config_file_parsing() {
    use softkms::Config;

    // Test that we can serialize and deserialize config
    let config = Config::default();

    // Serialize to TOML
    let toml_str = toml::to_string(&config).unwrap();

    // Deserialize back
    let parsed_config: Config = toml::from_str(&toml_str).unwrap();

    // Verify round-trip
    assert_eq!(config.api.grpc_addr, parsed_config.api.grpc_addr);
    assert_eq!(config.storage.backend, parsed_config.storage.backend);
}

/// Test build script
#[test]
fn test_build_script_exists() {
    let build_script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("build.sh");
    assert!(build_script.exists(), "build.sh should exist");

    // Check it's executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&build_script).unwrap();
        let permissions = metadata.permissions();
        assert!(
            permissions.mode() & 0o111 != 0,
            "build.sh should be executable"
        );
    }
}

/// Docker configuration exists
#[test]
fn test_docker_config_exists() {
    let dockerfile = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docker")
        .join("Dockerfile");

    assert!(
        dockerfile.exists()
            || std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("Dockerfile")
                .exists(),
        "Dockerfile should exist"
    );
}

/// Test project structure
#[test]
fn test_project_structure() {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

    // Required directories
    assert!(base.join("src").exists(), "src/ directory should exist");
    assert!(base.join("cli").exists(), "cli/ directory should exist");
    assert!(base.join("docs").exists(), "docs/ directory should exist");
    assert!(base.join("tests").exists(), "tests/ directory should exist");

    // Required files
    assert!(base.join("Cargo.toml").exists(), "Cargo.toml should exist");
    assert!(base.join("README.md").exists(), "README.md should exist");
}

/// Smoke test: verify cargo check passes
#[test]
#[ignore = "Takes too long for regular test runs"]
fn test_cargo_check() {
    let output = Command::new("cargo")
        .args(["check"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run cargo check");

    assert!(
        output.status.success(),
        "cargo check should pass:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Smoke test: verify cargo test compiles
#[test]
#[ignore = "Takes too long for regular test runs"]
fn test_cargo_test_compiles() {
    let output = Command::new("cargo")
        .args(["test", "--no-run"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to compile tests");

    assert!(
        output.status.success(),
        "cargo test --no-run should compile:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
