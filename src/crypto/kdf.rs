use sha2::{Digest, Sha256};

/// Derives a strict 32-byte master key from a user-provided password string.
/// 
/// *Note: In a production Zero-Trust Vault, this should eventually be 
/// upgraded to a memory-hard hashing algorithm like Argon2 with a random salt.*
pub fn derive_key_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    // Hash the raw string bytes
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    // Convert the resulting SHA-256 hash into a standard 32-byte array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}