//! Identity management module
//!
//! Provides identity-based access control with:
//! - ECC public key identities (Ed25519 default, P-256 optional)
//! - Bearer token authentication
//! - Namespace isolation per identity
//! - Role-based access (admin/client)

pub mod storage;
pub mod types;
pub mod validation;

pub use types::{Identity, IdentityRole, ClientType, IdentityKeyType, Token, IdentityError};
pub use storage::IdentityStore;
pub use validation::{validate_token, extract_token_from_request};
