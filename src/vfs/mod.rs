use crate::crypto::aes_gcm::{decrypt_data, encrypt_data, CryptoError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC_BYTES: &[u8; 8] = b"AEGISVFS";

/// Custom error type for VFS operations
#[derive(Debug)]
pub enum VfsError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Serialization(bincode::Error),
    InvalidFormat(String),
}

// -----------------------------------------------------------------------------
// ERROR HANDLING IMPLEMENTATIONS
// -----------------------------------------------------------------------------

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VfsError::Io(err) => write!(f, "I/O Error: {}", err),
            VfsError::Crypto(err) => write!(f, "Cryptography Error: {}", err),
            VfsError::Serialization(err) => write!(f, "Serialization Error: {}", err),
            VfsError::InvalidFormat(msg) => write!(f, "Invalid Vault Format: {}", msg),
        }
    }
}

impl std::error::Error for VfsError {}

// Allow seamless use of the `?` operator for standard errors
impl From<std::io::Error> for VfsError {
    fn from(err: std::io::Error) -> Self {
        VfsError::Io(err)
    }
}

impl From<bincode::Error> for VfsError {
    fn from(err: bincode::Error) -> Self {
        VfsError::Serialization(err)
    }
}

// -----------------------------------------------------------------------------
// VFS DATA STRUCTURES
// -----------------------------------------------------------------------------

/// Represents a single file inside the vault
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct FileEntry {
    pub offset: u64,
    pub size: u64,
    // Future additions: timestamps, permissions, etc.
}

/// The File Allocation Table (FAT) / Directory Structure
#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct VfsIndex {
    pub files: HashMap<String, FileEntry>,
}

/// The main Vault Container holding the in-memory state
pub struct VfsContainer {
    pub file_path: PathBuf,
    pub index: VfsIndex,
}

// -----------------------------------------------------------------------------
// VFS CORE LOGIC
// -----------------------------------------------------------------------------

impl VfsContainer {
    /// Initializes a brand new, empty `.aegis` vault on disk.
    pub fn init<P: AsRef<Path>>(file_path: P, key: &[u8; 32]) -> Result<Self, VfsError> {
        let path = file_path.as_ref().to_path_buf();
        let index = VfsIndex::default(); // Creates an empty file map

        // 1. Serialize the empty index to raw bytes
        let serialized_index = bincode::serialize(&index)?;

        // 2. Encrypt the serialized index
        let encrypted_index = encrypt_data(key, &serialized_index);

        // 3. Create the file and write the structure
        let mut file = File::create(&path)?;
        
        // Write Magic Bytes
        file.write_all(MAGIC_BYTES)?;
        
        // Write the length of the encrypted index payload as an 8-byte Little Endian integer
        let index_size = encrypted_index.len() as u64;
        file.write_all(&index_size.to_le_bytes())?;
        
        // Write the actual encrypted index
        file.write_all(&encrypted_index)?;

        Ok(Self { file_path: path, index })
    }

    /// Loads an existing `.aegis` vault from disk and decrypts its index.
    pub fn load<P: AsRef<Path>>(file_path: P, key: &[u8; 32]) -> Result<Self, VfsError> {
        let path = file_path.as_ref().to_path_buf();
        let mut file = OpenOptions::new().read(true).open(&path)?;

        // 1. Read and verify Magic Bytes
        let mut magic_buffer = [0u8; 8];
        file.read_exact(&mut magic_buffer)?;
        if &magic_buffer != MAGIC_BYTES {
            return Err(VfsError::InvalidFormat("Missing or invalid magic bytes".into()));
        }

        // 2. Read the size of the encrypted index
        let mut size_buffer = [0u8; 8];
        file.read_exact(&mut size_buffer)?;
        let index_size = u64::from_le_bytes(size_buffer);

        // 3. Read the encrypted index bytes
        let mut encrypted_index = vec![0u8; index_size as usize];
        file.read_exact(&mut encrypted_index)?;

        // 4. Decrypt the index payload
        let decrypted_index = decrypt_data(key, &encrypted_index)
            .map_err(VfsError::Crypto)?;

        // 5. Deserialize back into our Rust struct
        let index: VfsIndex = bincode::deserialize(&decrypted_index)?;

        Ok(Self { file_path: path, index })
    }
}

// -----------------------------------------------------------------------------
// TESTS
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_vfs_init_and_load_roundtrip() {
        let test_file = "test_vault.aegis";
        let master_key: [u8; 32] = [7; 32]; // Arbitrary key

        // Clean up any previous failed test runs
        let _ = fs::remove_file(test_file);

        // 1. Init a new container
        let init_result = VfsContainer::init(test_file, &master_key);
        assert!(init_result.is_ok(), "Failed to init vault");
        
        let mut container = init_result.unwrap();

        // Let's add a dummy file to the index to ensure state is saved correctly
        container.index.files.insert(
            "secrets.txt".to_string(),
            FileEntry { offset: 1024, size: 500 }
        );
        assert_eq!(container.index.files.len(), 1);

        // 2. Load the container back from disk
        // Since we didn't re-save to disk after adding the dummy file, 
        // the loaded container should have an empty index (len == 0).
        let load_result = VfsContainer::load(test_file, &master_key);
        assert!(load_result.is_ok(), "Failed to load vault");

        let loaded_container = load_result.unwrap();
        
        assert_eq!(loaded_container.file_path, PathBuf::from(test_file));
        assert_eq!(loaded_container.index.files.len(), 0); // Confirms we read the empty index from disk

        // Clean up the file system
        fs::remove_file(test_file).expect("Failed to clean up test file");
    }

    #[test]
    fn test_vfs_load_invalid_magic_bytes() {
        let test_file = "bad_vault.aegis";
        let master_key: [u8; 32] = [7; 32];

        // Create a fake, invalid file
        let mut file = File::create(test_file).unwrap();
        file.write_all(b"NOTAEGIS... some garbage data").unwrap();

        // Attempt to load
        let result = VfsContainer::load(test_file, &master_key);
        
        assert!(matches!(result, Err(VfsError::InvalidFormat(_))));

        fs::remove_file(test_file).unwrap();
    }
}