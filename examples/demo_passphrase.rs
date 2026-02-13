//! Example: Trigger passphrase prompt
//!
//! This demonstrates how the passphrase is prompted when you
//! actually try to store or retrieve encrypted data.

use softkms::storage::encrypted::create_encrypted_storage;
use softkms::storage::StorageBackend;
use softkms::{Config, KeyId, KeyMetadata, KeyType};
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    println!("=== Passphrase Prompt Demo ===\n");
    
    // Setup
    let config = Config::default();
    let storage_path = PathBuf::from("/home/user/.softKMS-demo/data");
    
    println!("Creating encrypted storage...");
    println!("(This does NOT prompt for passphrase yet)\n");
    
    // This creates the storage but doesn't access it
    let storage = create_encrypted_storage(
        storage_path,
        config,
        300, // 5 minute cache
    ).expect("Failed to create storage");
    
    println!("✓ Storage created\n");
    
    // Initialize (creates directories, doesn't prompt)
    println!("Initializing storage...");
    storage.init().await.expect("Failed to init");
    println!("✓ Storage initialized (still no prompt)\n");
    
    // NOW we try to store a key - THIS will prompt for passphrase
    println!("========================================");
    println!("NOW attempting to store a key...");
    println!("THIS WILL PROMPT FOR PASSPHRASE");
    println!("========================================\n");
    
    let key_id = KeyId::new_v4();
    let metadata = KeyMetadata {
        id: key_id,
        label: Some("Test Key".to_string()),
        algorithm: "ed25519".to_string(),
        key_type: KeyType::Imported,
        created_at: chrono::Utc::now(),
        attributes: std::collections::HashMap::new(),
    };
    
    // This will prompt: "Enter passphrase: "
    let key_material = b"my_secret_key_material_that_needs_encryption!";
    
    match storage.store_key(key_id, &metadata, key_material).await {
        Ok(()) => println!("\n✓ Key stored successfully!"),
        Err(e) => println!("\n✗ Error: {}", e),
    }
    
    // Now try to retrieve it - should use cached passphrase
    println!("\n========================================");
    println!("Retrieving the same key...");
    println!("Should use cached passphrase (no prompt)");
    println!("========================================\n");
    
    match storage.retrieve_key(key_id).await {
        Ok(Some((retrieved_metadata, decrypted))) => {
            println!("✓ Key retrieved successfully!");
            println!("  - Label: {:?}", retrieved_metadata.label);
            println!("  - Decrypted length: {} bytes", decrypted.len());
            assert_eq!(key_material.to_vec(), decrypted);
            println!("  - Data matches: ✓");
        }
        Ok(None) => println!("Key not found"),
        Err(e) => println!("✗ Error: {}", e),
    }
    
    println!("\n=== Demo Complete ===");
    println!("\nKey points:");
    println!("  1. Daemon startup: No passphrase needed");
    println!("  2. First key operation: Prompts for passphrase");
    println!("  3. Subsequent operations: Uses cached passphrase (5 min TTL)");
    println!("  4. After TTL expires: Prompts again");
}
