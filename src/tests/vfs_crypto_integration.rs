// tests/vfs_crypto_integration.rs

use zero_trust_vault::crypto::aes_gcm::{decrypt_data, encrypt_data, CryptoError};

#[test]
fn test_vfs_header_encryption_workflow() {
    // 1. Simulate the vault master key (derived from user password)
    let master_key: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    // 2. Simulate serializing your Application-Level VFS File Map (e.g., JSON bytes)
    let simulated_vfs_header = b"{ \"files\": [\"secret.pdf\", \"passwords.txt\"] }";

    // 3. Encrypt the VFS map to store at the beginning of your vault file
    let encrypted_header = encrypt_data(&master_key, simulated_vfs_header);

    // 4. Simulate the app starting up and reading the header back from disk
    let decrypted_header = decrypt_data(&master_key, &encrypted_header)
        .expect("Integration failed: Unable to decrypt VFS header");

    // 5. Verify the VFS map is perfectly intact
    assert_eq!(decrypted_header, simulated_vfs_header);
}

#[test]
fn test_vfs_rejects_corrupted_vault_file() {
    let master_key: [u8; 32] = [99; 32];
    
    // Simulate writing an encrypted file block to disk
    let mut disk_block = encrypt_data(&master_key, b"Binary file data chunk");
    
    // Simulate disk rot, or a malicious actor altering the vault file
    disk_block[20] ^= 0xFF; 

    // Ensure the VFS securely rejects the block rather than passing bad data to the UI
    let result = decrypt_data(&master_key, &disk_block);
    assert_eq!(result, Err(CryptoError::DecryptionFailed));
}
