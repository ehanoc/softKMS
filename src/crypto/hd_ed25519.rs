//! HD Wallet Ed25519 (BIP32) implementation
//!
//! Provides hierarchical deterministic key derivation for Ed25519 keys
//! using the xHD-Wallet-API-rs crate with support for:
//! - BIP32/BIP44 derivation paths
//! - Peikert scheme (default) and V2 (Khovratovich) scheme
//! - Public key derivation from xpub
//! - Bech32 address encoding

use ed25519_bip32::{DerivationIndex, DerivationScheme, XPrv, XPub, XPRV_SIZE, XPUB_SIZE};
use std::convert::TryInto;

/// Errors that can occur during HD derivation
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("Invalid seed length: expected 64, got {0}")]
    InvalidSeedLength(usize),
    #[error("Invalid xpub length: expected {XPUB_SIZE}, got {0}")]
    InvalidXpubLength(usize),
    #[error("Invalid xprv length: expected {XPRV_SIZE}, got {0}")]
    InvalidXprvLength(usize),
    #[error("Hardened derivation not possible from xpub")]
    HardenedFromXpub,
    #[error("Derivation failed: {0}")]
    DerivationFailed(String),
}

/// Result type for HD operations
pub type Result<T> = std::result::Result<T, HdError>;

/// Derivation scheme for Ed25519 keys
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HdDerivationScheme {
    /// Peikert scheme (enhanced entropy, default)
    Peikert,
    /// V2 scheme (original IEEE BIP32-Ed25519 standard)
    V2,
}

impl Default for HdDerivationScheme {
    fn default() -> Self {
        HdDerivationScheme::Peikert
    }
}

impl From<HdDerivationScheme> for DerivationScheme {
    fn from(scheme: HdDerivationScheme) -> Self {
        match scheme {
            HdDerivationScheme::Peikert => DerivationScheme::Peikert,
            HdDerivationScheme::V2 => DerivationScheme::V2,
        }
    }
}

/// A derived Ed25519 key with extended key material
pub struct DerivedKey {
    /// Extended private key
    pub xprv: XPrv,
    /// Extended public key
    pub xpub: XPub,
    /// 32-byte public key
    pub public_key: [u8; 32],
    /// 32-byte chain code
    pub chain_code: [u8; 32],
    /// Derivation path used
    pub path: String,
}

/// Public key derived from xpub (no private key access)
pub struct DerivedPublicKey {
    /// 32-byte public key
    pub public_key: [u8; 32],
    /// 32-byte chain code
    pub chain_code: [u8; 32],
    /// Child index
    pub index: u32,
}

/// HD Ed25519 engine for key derivation and signing
pub struct HdEd25519Engine {
    scheme: HdDerivationScheme,
}

impl HdEd25519Engine {
    /// Create a new engine with the given derivation scheme
    pub fn new(scheme: HdDerivationScheme) -> Self {
        Self { scheme }
    }

    /// Create a new engine with the default scheme (Peikert)
    pub fn new_default() -> Self {
        Self {
            scheme: HdDerivationScheme::default(),
        }
    }

    /// Derive an Ed25519 key from a seed using a BIP44 path
    ///
    /// BIP44 path format: m/44'/coin_type'/account'/change/address_index
    /// All levels except the last two are hardened (')
    pub fn derive_bip44(
        &self,
        seed: &[u8],
        coin_type: u32,
        account: u32,
        change: u32,
        address_index: u32,
    ) -> Result<DerivedKey> {
        let path = format!("m/44'/{coin_type}'/{account}'/{change}/{address_index}");
        self.derive_path(seed, &path)
    }

    /// Derive an Ed25519 key from a seed using a custom derivation path
    ///
    /// Path format examples:
    /// - "m/44'/283'/0'/0/0" (BIP44 for Algorand)
    /// - "m/0" (simple non-hardened)
    /// - "m/0'/1'" (hardened)
    ///
    /// Hardened indices are marked with ' and cannot be derived from xpub
    pub fn derive_path(&self, seed: &[u8], path: &str) -> Result<DerivedKey> {
        let seed_len = seed.len();
        if seed_len != 64 {
            return Err(HdError::InvalidSeedLength(seed_len));
        }

        let seed_array: &[u8; 64] = seed
            .try_into()
            .map_err(|_| HdError::InvalidSeedLength(seed.len()))?;

        let xprv = XPrv::from_seed(seed_array);

        // Parse and validate path
        let indices = parse_derivation_path(path)?;

        // Derive along path
        let mut current_xprv = xprv;
        for index in indices {
            let scheme: DerivationScheme = self.scheme.into();
            current_xprv = current_xprv.derive(scheme, index);
        }

        let derived_xpub = current_xprv.public();
        let derived_public_key = derived_xpub.public_key();
        let derived_chain_code = derived_xpub.chain_code();

        Ok(DerivedKey {
            xprv: current_xprv,
            xpub: derived_xpub,
            public_key: derived_public_key,
            chain_code: *derived_chain_code,
            path: path.to_string(),
        })
    }

    /// Sign data with a derived key
    pub fn sign(&self, xprv: &XPrv, data: &[u8]) -> ed25519_bip32::Signature<()> {
        xprv.sign(data)
    }

    /// Derive a child public key from an xpub (soft derivation only)
    ///
    /// This allows deriving public keys without access to the private key,
    /// useful for watch-only wallets. Cannot derive hardened indices.
    pub fn derive_public(&self, xpub: &XPub, index: u32) -> Result<DerivedPublicKey> {
        // Check if index is hardened (>= 2^31)
        if index >= 0x8000_0000 {
            return Err(HdError::HardenedFromXpub);
        }

        let scheme: DerivationScheme = self.scheme.into();
        let derived = xpub
            .derive(scheme, index)
            .map_err(|e| HdError::DerivationFailed(e.to_string()))?;

        Ok(DerivedPublicKey {
            public_key: derived.public_key(),
            chain_code: *derived.chain_code(),
            index,
        })
    }

    /// Create an XPrv from raw bytes
    pub fn xprv_from_bytes(bytes: &[u8]) -> Result<XPrv> {
        let arr: &[u8; XPRV_SIZE] = bytes
            .try_into()
            .map_err(|_| HdError::InvalidXprvLength(bytes.len()))?;
        XPrv::from_slice_verified(arr).map_err(|e| HdError::DerivationFailed(e.to_string()))
    }

    /// Create an XPub from raw bytes
    pub fn xpub_from_bytes(bytes: &[u8]) -> Result<XPub> {
        XPub::from_slice(bytes).map_err(|e| HdError::DerivationFailed(e.to_string()))
    }

    /// Serialize XPrv to bytes
    pub fn xprv_to_bytes(xprv: &XPrv) -> [u8; XPRV_SIZE] {
        let bytes: &[u8] = xprv.as_ref();
        bytes.try_into().expect("XPRV_SIZE should match")
    }

    /// Serialize XPub to bytes
    pub fn xpub_to_bytes(xpub: &XPub) -> [u8; XPUB_SIZE] {
        let bytes: &[u8] = xpub.as_ref();
        bytes.try_into().expect("XPUB_SIZE should match")
    }
}

/// Parse a BIP32 derivation path string into indices
fn parse_derivation_path(path: &str) -> Result<Vec<DerivationIndex>> {
    let mut indices = Vec::new();

    // Handle empty path or root only
    let path = path.trim();
    if path.is_empty() || path == "m" || path == "M" {
        return Ok(indices); // Root key
    }

    // Remove leading 'm/' or 'M/' if present
    let path = if path.starts_with("m/") || path.starts_with("M/") {
        &path[2..]
    } else {
        path
    };

    for component in path.split('/') {
        let component = component.trim();
        if component.is_empty() {
            return Err(HdError::InvalidPath(format!(
                "Empty path component in '{path}'"
            )));
        }

        let (index_str, hardened) = if component.ends_with('\'') || component.ends_with('h') {
            (&component[..component.len() - 1], true)
        } else {
            (component, false)
        };

        let index: u32 = index_str
            .parse()
            .map_err(|_| HdError::InvalidPath(format!("Invalid index '{component}' in path")))?;

        // Hardened indices add 2^31
        let derivation_index = if hardened {
            index.checked_add(0x8000_0000).ok_or_else(|| {
                HdError::InvalidPath(format!("Index too large for hardening: {index}"))
            })?
        } else {
            index
        };

        indices.push(derivation_index);
    }

    Ok(indices)
}

/// Encode a public key as a Bech32 address
pub fn encode_bech32(hrp: &str, public_key: &[u8; 32]) -> String {
    let hrp = match bech32::Hrp::parse(hrp) {
        Ok(h) => h,
        Err(e) => return format!("{hrp}:INVALID:{e}"),
    };
    let encoded = bech32::encode::<bech32::Bech32m>(hrp, public_key);
    match encoded {
        Ok(addr) => addr,
        Err(e) => format!("{}:INVALID:{e}", hrp.as_str()),
    }
}

/// Decode a Bech32 address to get the public key
pub fn decode_bech32(address: &str) -> Option<(String, [u8; 32])> {
    let decoded = bech32::decode(address).ok()?;
    let (hrp, data) = decoded;

    if data.len() != 32 {
        return None;
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data);
    Some((hrp.as_str().to_string(), public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test seed from xHD-Wallet-API-rs
    const TEST_SEED_HEX: &str = "3aff2db416b895ec3cf9a4f8d1e970bc9819920e7bf44a5e350477af0ef557b1511b0986debf78dd38c7c520cd44ff7c7231618f958e21ef0250733a8c1915ea";
    /// Expected root key in hex
    const ROOT_KEY_HEX: &str = "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f4694592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_parse_derivation_path() {
        assert_eq!(parse_derivation_path("m/0/1").unwrap(), vec![0, 1]);
        assert_eq!(parse_derivation_path("0/1").unwrap(), vec![0, 1]);
        assert_eq!(
            parse_derivation_path("m/44'/0'/0'").unwrap(),
            vec![0x8000_0000 + 44, 0x8000_0000 + 0, 0x8000_0000 + 0,]
        );
        assert_eq!(
            parse_derivation_path("m/44'/0'/0/1").unwrap(),
            vec![0x8000_0000 + 44, 0x8000_0000 + 0, 0, 1,]
        );
        assert_eq!(
            parse_derivation_path("m/44h/0h/0h").unwrap(),
            vec![0x8000_0000 + 44, 0x8000_0000 + 0, 0x8000_0000 + 0,]
        );
        assert_eq!(parse_derivation_path("m").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_derivation_path("").unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn test_parse_invalid_paths() {
        assert!(parse_derivation_path("m//1").is_err());
        assert!(parse_derivation_path("m/abc").is_err());
        assert!(parse_derivation_path("m/4294967296").is_err());
    }

    #[test]
    fn test_bech32_roundtrip() {
        let public_key = [0u8; 32];
        let address = encode_bech32("algo", &public_key);
        let decoded = decode_bech32(&address).unwrap();
        assert_eq!(decoded.0, "algo");
        assert_eq!(decoded.1, public_key);
    }

    #[test]
    fn test_bech32_different_prefixes() {
        let public_key = [0xabu8; 32];
        let algo_addr = encode_bech32("algo", &public_key);
        let test_addr = encode_bech32("test", &public_key);
        assert!(algo_addr.starts_with("algo1"));
        assert!(test_addr.starts_with("test1"));
        assert_ne!(algo_addr, test_addr);
    }

    #[test]
    fn test_engine_creation() {
        let engine_peikert = HdEd25519Engine::new(HdDerivationScheme::Peikert);
        assert_eq!(engine_peikert.scheme, HdDerivationScheme::Peikert);
        let engine_v2 = HdEd25519Engine::new(HdDerivationScheme::V2);
        assert_eq!(engine_v2.scheme, HdDerivationScheme::V2);
        let engine_default = HdEd25519Engine::new_default();
        assert_eq!(engine_default.scheme, HdDerivationScheme::Peikert);
    }

    #[test]
    fn test_seed_from_reference() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        assert_eq!(seed.len(), 64);
        let engine = HdEd25519Engine::new_default();
        let derived = engine.derive_path(&seed, "m").unwrap();
        let xprv_bytes: [u8; XPRV_SIZE] = derived.xprv.into();
        assert_eq!(hex::encode(&xprv_bytes), ROOT_KEY_HEX);
    }

    #[test]
    fn test_bip44_derivation_algorand() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new(HdDerivationScheme::Peikert);
        let derived = engine
            .derive_bip44(&seed, 283, 0, 0, 0)
            .expect("Derivation should succeed");
        let expected_pubkey = "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9";
        assert_eq!(hex::encode(derived.public_key), expected_pubkey);
        let address = encode_bech32("algo", &derived.public_key);
        assert!(address.starts_with("algo1"));
    }

    #[test]
    fn test_peikert_vs_v2_produces_different_keys() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let path = "m/44'/283'/0'/0/0";
        let peikert_engine = HdEd25519Engine::new(HdDerivationScheme::Peikert);
        let v2_engine = HdEd25519Engine::new(HdDerivationScheme::V2);
        let peikert_key = peikert_engine.derive_path(&seed, path).unwrap();
        let v2_key = v2_engine.derive_path(&seed, path).unwrap();
        assert_ne!(peikert_key.public_key, v2_key.public_key);
    }

    #[test]
    fn test_signing_with_derived_key() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new_default();
        let derived = engine.derive_bip44(&seed, 283, 0, 0, 0).unwrap();
        let message = b"Hello, World!";
        let signature = engine.sign(&derived.xprv, message);
        assert_eq!(signature.to_bytes().len(), 64);
        assert!(derived.xpub.verify(message, &signature));
    }

    #[test]
    fn test_soft_derivation_from_xpub() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new_default();
        let scheme = HdDerivationScheme::Peikert;

        // Derive to account level: m/44'/283'/0'
        let wallet_level = engine.derive_path(&seed, "m/44'/283'/0'").unwrap();

        // From account xpub, derive change=0, then address_index=0 and 1
        // This requires TWO derivations per BIP44 path structure
        let scheme_internal: ed25519_bip32::DerivationScheme = scheme.into();

        // First derive to change level (0 = external)
        let change_xpub = wallet_level
            .xpub
            .derive(scheme_internal, 0)
            .expect("Failed to derive change level");

        // Then derive to address level
        let addr_0_xpub = change_xpub
            .derive(scheme_internal, 0)
            .expect("Failed to derive address 0");
        let addr_1_xpub = change_xpub
            .derive(scheme_internal, 1)
            .expect("Failed to derive address 1");

        // Derive same addresses from private path
        let child_0_private = engine.derive_path(&seed, "m/44'/283'/0'/0/0").unwrap();
        let child_1_private = engine.derive_path(&seed, "m/44'/283'/0'/0/1").unwrap();

        // Compare public keys
        assert_eq!(addr_0_xpub.public_key(), child_0_private.public_key);
        assert_eq!(addr_1_xpub.public_key(), child_1_private.public_key);
        assert_eq!(*addr_0_xpub.chain_code(), child_0_private.chain_code);
    }

    #[test]
    fn test_hardened_derivation_from_xpub_fails() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new_default();
        let wallet_level = engine.derive_path(&seed, "m/44'/283'/0'").unwrap();
        let result = engine.derive_public(&wallet_level.xpub, 0x8000_0000);
        assert!(matches!(result, Err(HdError::HardenedFromXpub)));
    }

    #[test]
    fn test_xpub_xprv_serialization() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new_default();
        let derived = engine.derive_bip44(&seed, 283, 0, 0, 0).unwrap();
        let xprv_bytes = HdEd25519Engine::xprv_to_bytes(&derived.xprv);
        let xprv_restored = HdEd25519Engine::xprv_from_bytes(&xprv_bytes).unwrap();
        let xpub_bytes = HdEd25519Engine::xpub_to_bytes(&derived.xpub);
        let xpub_restored = HdEd25519Engine::xpub_from_bytes(&xpub_bytes).unwrap();
        assert_eq!(HdEd25519Engine::xprv_to_bytes(&xprv_restored), xprv_bytes);
        assert_eq!(HdEd25519Engine::xpub_to_bytes(&xpub_restored), xpub_bytes);
    }

    #[test]
    fn test_different_coin_types() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new_default();
        let algo_key = engine.derive_bip44(&seed, 283, 0, 0, 0).unwrap();
        let identity_key = engine.derive_bip44(&seed, 0, 0, 0, 0).unwrap();
        assert_ne!(algo_key.public_key, identity_key.public_key);
    }

    #[test]
    fn test_multiple_accounts() {
        let seed = hex_to_bytes(TEST_SEED_HEX);
        let engine = HdEd25519Engine::new_default();
        let account0 = engine.derive_bip44(&seed, 283, 0, 0, 0).unwrap();
        let account1 = engine.derive_bip44(&seed, 283, 1, 0, 0).unwrap();
        let account2 = engine.derive_bip44(&seed, 283, 2, 0, 0).unwrap();
        assert_ne!(account0.public_key, account1.public_key);
        assert_ne!(account1.public_key, account2.public_key);
        assert_ne!(account0.public_key, account2.public_key);
    }

    #[test]
    fn test_invalid_seed_lengths() {
        let engine = HdEd25519Engine::new_default();
        assert!(engine.derive_path(&[0u8; 32], "m/0").is_err());
        assert!(engine.derive_path(&[0u8; 128], "m/0").is_err());
    }

    #[test]
    fn test_invalid_xprv_xpub_bytes() {
        assert!(HdEd25519Engine::xprv_from_bytes(&[0u8; 32]).is_err());
        assert!(HdEd25519Engine::xprv_from_bytes(&[0u8; 200]).is_err());
        assert!(HdEd25519Engine::xpub_from_bytes(&[0u8; 32]).is_err());
        assert!(HdEd25519Engine::xpub_from_bytes(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_bech32_with_different_data() {
        let data1 = [0xabu8; 32];
        let data2 = [0x00u8; 32];
        let addr1 = encode_bech32("algo", &data1);
        let addr2 = encode_bech32("algo", &data2);
        assert_ne!(addr1, addr2);
        let decoded1 = decode_bech32(&addr1).unwrap();
        let decoded2 = decode_bech32(&addr2).unwrap();
        assert_eq!(decoded1.0, "algo");
        assert_eq!(decoded2.0, "algo");
        assert_eq!(decoded1.1, data1);
        assert_eq!(decoded2.1, data2);
    }

    #[test]
    fn test_bech32_invalid_address() {
        assert!(decode_bech32("not-a-valid-bech32").is_none());
        assert!(decode_bech32("").is_none());
        assert!(decode_bech32("algo").is_none());
    }
}
