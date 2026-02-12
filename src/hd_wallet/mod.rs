//! HD Wallet support (BIP32, BIP44, ARC-0052)

/// HD wallet seed
pub struct Seed {
    /// Seed ID
    pub id: crate::KeyId,
    /// Seed material (master key)
    pub material: secrecy::Secret<Vec<u8>>,
    /// Metadata
    pub metadata: crate::KeyMetadata,
}

/// Derivation path (e.g., "m/44'/283'/0'/0/0")
pub struct DerivationPath {
    /// Path components
    pub components: Vec<u32>,
}

/// Derive a key from seed using path
pub fn derive_key(seed: &Seed, path: &DerivationPath) -> crate::Result<Seed> {
    // TODO: Implement BIP32 derivation
    unimplemented!("BIP32 derivation")
}