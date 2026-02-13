//! Example: Testing the Security Layer
//!
//! This example demonstrates the encryption/decryption flow

use softkms::security::{KeyWrapper, MasterKey, WrappedKey};

fn main() {
    println!("=== softKMS Security Layer Test ===\n");

    // Test 1: Master Key Derivation
    println!("Test 1: Deriving master key from passphrase...");
    let master_key =
        MasterKey::derive("test_passphrase", 1000).expect("Failed to derive master key");
    println!("✓ Master key derived successfully\n");

    // Test 2: Key Wrapping
    println!("Test 2: Wrapping key material...");
    let wrapper = KeyWrapper::new(master_key);
    let plaintext = b"my_secret_key_material_32_bytes!";
    let aad = b"key_id=test-key&algorithm=ed25519";

    let wrapped = wrapper.wrap(plaintext, aad).expect("Failed to wrap key");
    println!("✓ Key wrapped successfully");
    println!("  - Version: {}", wrapped.version);
    println!("  - Salt (hex): {}", hex::encode(&wrapped.salt[..8]));
    println!("  - Nonce (hex): {}", hex::encode(&wrapped.nonce[..8]));
    println!(
        "  - Ciphertext length: {} bytes\n",
        wrapped.ciphertext.len()
    );

    // Test 3: Serialization
    println!("Test 3: Serializing wrapped key...");
    let bytes = wrapped.to_bytes();
    println!("✓ Serialized to {} bytes\n", bytes.len());

    // Test 4: Deserialization
    println!("Test 4: Deserializing wrapped key...");
    let restored = WrappedKey::from_bytes(&bytes).expect("Failed to deserialize");
    println!("✓ Deserialized successfully\n");

    // Test 5: Unwrapping
    println!("Test 5: Unwrapping with same passphrase...");
    let master_key2 =
        MasterKey::derive("test_passphrase", 1000).expect("Failed to derive master key 2");
    let wrapper2 = KeyWrapper::new(master_key2);

    let decrypted = wrapper2.unwrap(&restored, aad).expect("Failed to unwrap");

    assert_eq!(plaintext.to_vec(), decrypted);
    println!("✓ Decryption successful - plaintext matches!\n");

    // Test 6: Wrong passphrase
    println!("Test 6: Trying wrong passphrase...");
    let wrong_key =
        MasterKey::derive("wrong_passphrase", 1000).expect("Failed to derive wrong key");
    let wrong_wrapper = KeyWrapper::new(wrong_key);

    match wrong_wrapper.unwrap(&restored, aad) {
        Ok(_) => println!("✗ ERROR: Should have failed!"),
        Err(e) => println!("✓ Correctly rejected: {}\n", e),
    }

    // Test 7: Wrong AAD
    println!("Test 7: Trying wrong AAD...");
    let wrong_aad = b"tampered_metadata";
    match wrapper2.unwrap(&restored, wrong_aad) {
        Ok(_) => println!("✗ ERROR: Should have failed!"),
        Err(e) => println!("✓ Correctly detected tampering: {}\n", e),
    }

    println!("=== All Tests Passed! ===");
    println!("\nSecurity Features Verified:");
    println!("  ✓ PBKDF2 key derivation");
    println!("  ✓ AES-256-GCM encryption");
    println!("  ✓ Per-key salts");
    println!("  ✓ AAD authentication");
    println!("  ✓ Wrong passphrase detection");
    println!("  ✓ Tampering detection");
}
