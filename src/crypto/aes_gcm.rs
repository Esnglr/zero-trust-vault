use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use std::fmt;

/// Custom error type for cryptographic operations
#[derive(Debug, PartialEq)]
pub enum CryptoError {
    InvalidLength,
    DecryptionFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidLength => write!(f, "Ciphertext is too short to contain a valid nonce"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed: invalid key or corrupted data"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Encrypts a byte array using AES-256-GCM.
/// Generates a random 96-bit (12-byte) nonce and prepends it to the ciphertext.
pub fn encrypt_data(key_bytes: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let key: &Key<Aes256Gcm> = key_bytes.into();
    let cipher = Aes256Gcm::new(key);

    // Generate a secure, 96-bit unique nonce per encryption
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt the data. The 16-byte MAC tag is automatically appended.
    let ciphertext = cipher.encrypt(&nonce, data).expect("Encryption memory allocation failed");

    // Prepend the 12-byte nonce to the ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);

    result
}

/// Decrypts a byte array encrypted by `encrypt_data`.
/// Extracts the 96-bit prepended nonce, verifies the MAC tag, and decrypts.
pub fn decrypt_data(key_bytes: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // 12 bytes for the nonce is the absolute minimum requirement.
    if payload.len() < 12 {
        return Err(CryptoError::InvalidLength);
    }

    // Split the prepended nonce from the rest of the payload
    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Initialize the cipher
    let key: &Key<Aes256Gcm> = key_bytes.into();
    let cipher = Aes256Gcm::new(key);

    // Decrypt the payload and map errors to our secure CryptoError
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

// -----------------------------------------------------------------------------
// STANDARD UNIT TESTS
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key: [u8; 32] = [42; 32]; 
        let plaintext = b"Hello Secure Vault";

        let encrypted = encrypt_data(&key, plaintext);
        
        // 12 (nonce) + plaintext length + 16 (MAC tag)
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);
        assert_ne!(encrypted, plaintext);

        let decrypted = decrypt_data(&key, &encrypted).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_invalid_length() {
        let key: [u8; 32] = [42; 32];
        let short_ciphertext = vec![0u8; 10]; // Less than 12 bytes

        let result = decrypt_data(&key, &short_ciphertext);
        assert_eq!(result, Err(CryptoError::InvalidLength));
    }

    #[test]
    fn test_decrypt_tampered_data() {
        let key: [u8; 32] = [42; 32];
        let mut encrypted = encrypt_data(&key, b"Sensitive Data");
        
        // Flip a bit in the ciphertext (simulates tampering or disk rot)
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 1;

        let result = decrypt_data(&key, &encrypted);
        assert_eq!(result, Err(CryptoError::DecryptionFailed));
    }
}

// -----------------------------------------------------------------------------
// PROPERTY-BASED TESTS
// -----------------------------------------------------------------------------
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use proptest::collection::vec;

    proptest! {
        #[test]
        fn test_encrypt_decrypt_never_panics(
            key_bytes in any::<[u8; 32]>(),
            data in vec(any::<u8>(), 0..10_000) 
        ) {
            let encrypted = encrypt_data(&key_bytes, &data);
            
            // Ciphertext must always be exactly 28 bytes larger than plaintext
            prop_assert_eq!(encrypted.len(), data.len() + 28);

            let decrypted = decrypt_data(&key_bytes, &encrypted)
                .expect("Valid ciphertext must always decrypt");

            prop_assert_eq!(data, decrypted);
        }
    }
}