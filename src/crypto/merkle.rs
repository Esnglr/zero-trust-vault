use sha2::{Digest, Sha256};

pub const BLOCK_SIZE: usize = 4096; // Standard 4KB block size

/// Represents a single chunk of file data.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub data: Vec<u8>,
}

impl Block {
    /// Helper to create a new block. In a real scenario, this would enforce
    /// the 4KB size limit or pad the data if it's the last block of a file.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// The Merkle Tree structure holding the root hash and all layers for verification.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root_hash: Vec<u8>,
    pub leaves: Vec<Vec<u8>>,
    pub layers: Vec<Vec<Vec<u8>>>,
}

/// Hashes a single byte slice (leaf node) using SHA-256.
pub fn hash_block(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Combines two child hashes to create a parent node hash.
pub fn combine_hashes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

impl MerkleTree {
    /// Builds a completely new Merkle Tree from a list of data blocks.
    pub fn new(blocks: &[Block]) -> Self {
        if blocks.is_empty() {
            return Self {
                root_hash: vec![],
                leaves: vec![],
                layers: vec![],
            };
        }

        // 1. Hash all the raw data blocks to create the bottom layer (leaves)
        let leaves: Vec<Vec<u8>> = blocks.iter().map(|b| hash_block(&b.data)).collect();
        let mut layers = vec![leaves.clone()];

        // 2. Iteratively build the tree upwards until we reach the single root node
        let mut current_layer = leaves.clone();
        
        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();
            
            // Process the current layer in pairs
            for chunk in current_layer.chunks(2) {
                if chunk.len() == 2 {
                    next_layer.push(combine_hashes(&chunk[0], &chunk[1]));
                } else {
                    // If there's an odd number of nodes, standard Merkle Tree protocol 
                    // dictates we duplicate the last node to combine it with itself.
                    next_layer.push(combine_hashes(&chunk[0], &chunk[0]));
                }
            }
            
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        // 3. The final layer contains exactly one hash: The Root Hash
        let root_hash = current_layer[0].clone();

        Self {
            root_hash,
            leaves,
            layers,
        }
    }
}

// -----------------------------------------------------------------------------
// TESTS
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_tamper_detection() {
        // Arrange: Create 3 identical 4KB blocks
        let b1 = Block::new(vec![1; BLOCK_SIZE]);
        let b2 = Block::new(vec![2; BLOCK_SIZE]);
        let b3 = Block::new(vec![3; BLOCK_SIZE]);
        
        let original_blocks = vec![b1.clone(), b2.clone(), b3.clone()];
        
        // Act: Build the original tree
        let original_tree = MerkleTree::new(&original_blocks);

        // Tamper: Modify a SINGLE byte deep inside block 2
        let mut tampered_b2 = b2.clone();
        tampered_b2.data[2048] = 99; 
        
        let tampered_blocks = vec![b1, tampered_b2, b3];
        
        // Act: Build the new tree from the tampered data
        let tampered_tree = MerkleTree::new(&tampered_blocks);

        // Assert: The root hashes must be completely different
        assert_ne!(
            original_tree.root_hash, 
            tampered_tree.root_hash, 
            "Root hash failed to catch the tampered byte!"
        );
        
        // Bonus Assert: Ensure the tree height is correct. 
        // 3 leaves -> 2 nodes -> 1 root = 3 layers
        assert_eq!(original_tree.layers.len(), 3);
    }

    #[test]
    fn test_empty_merkle_tree() {
        let empty_blocks: Vec<Block> = vec![];
        let tree = MerkleTree::new(&empty_blocks);
        
        assert!(tree.root_hash.is_empty());
        assert!(tree.layers.is_empty());
    }
}