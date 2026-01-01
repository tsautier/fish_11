pub mod x25519;
pub use self::x25519::*;

use crate::error::Result;

/// Trait for Key Exchange operations
pub trait KeyExchange {
    fn generate_keypair(&self) -> Result<Box<dyn KeyPair>>;
    fn extract_public_key(&self, formatted: &str) -> Result<Vec<u8>>;
}

/// Trait for Key Pair operations
pub trait KeyPair {
    fn public_key_formatted(&self) -> String;
    fn compute_shared_secret(&self, public_key: &[u8]) -> Result<[u8; 32]>;
    fn as_any(&self) -> &dyn std::any::Any;
}
