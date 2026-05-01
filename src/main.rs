use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Replace `zero_trust_vault` with the actual name of your crate from Cargo.toml
use zero_trust_vault::vfs::{FileMetadata, VfsContainer, VfsNode};

fn main() -> rustyline::Result<()> {
    // 1. Setup Master Key and Vault Path (Hardcoded for now)
    let master_key: [u8; 32] = [42; 32];
    let vault_path = "my_secure_vault.aegis";

    // 2. Initialize or Load the Vault
    let mut vault = VfsContainer::load(vault_path, &master_key).unwrap_or_else(|_| {
        println!("Creating new vault: {}", vault_path);
        VfsContainer::init(vault_path, &master_key).expect("Critical Error: Cannot create vault")
    });

    // --- TEMPORARY: Seed some dummy directories and files for testing ---
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    let mut docs_dir = HashMap::new();
    docs_dir.insert(
        "passwords.kdbx".to_string(),
        VfsNode::File(FileMetadata { offset: 1200, size: 1024, timestamp: now }),
    );
    
    vault.index.root.insert("docs".to_string(), VfsNode::Directory(docs_dir));
    vault.index.root.insert(
        "readme.txt".to_string(),
        VfsNode::File(FileMetadata { offset: 800, size: 42, timestamp: now }),
    );
    // -------------------------------------------------------------------

    // 3. Setup the Interactive Shell
    let mut rl = DefaultEditor::new()?;
    
    // Tracks the current directory state (e.g., ["docs", "finance"] represents /docs/finance)
    let mut current_path: Vec<String> = Vec::new();

    println!("========================================");
    println!("🛡️  Zero-Trust Vault Interactive Shell");
    println!("Type 'help' for commands, 'exit' to quit");
    println!("========================================");

    // 4. The REPL Loop
    loop {
        // Build the dynamic prompt (e.g., aegis:/docs> )
        let display_path = if current_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", current_path.join("/"))
        };
        let prompt = format!("zero-trust-vault:{} > ", display_path);

        // Read input
        let readline = rl.readline(&prompt);
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                rl.add_history_entry(line)?; // Allows hitting the 'Up' arrow to see previous commands

                // Parse command and argument
                let mut parts = line.split_whitespace();
                let cmd = parts.next().unwrap_or("");
                let arg = parts.next().unwrap_or("");

                match cmd {
                    "exit" | "quit" => {
                        println!("Locking vault and exiting...");
                        break;
                    }
                    "help" => {
                        println!("Available commands:");
                        println!("  ls        - List contents of the current directory");
                        println!("  cd <dir>  - Change directory (supports 'cd ..' and 'cd /')");
                        println!("  exit      - Lock and close the vault");
                    }
                    "ls" => {
                        // Fetch the current directory map from our VFS tree
                        if let Some(dir) = vault.get_directory(&current_path) {
                            if dir.is_empty() {
                                println!("  (empty)");
                            } else {
                                // Sort keys alphabetically for cleaner output
                                let mut keys: Vec<&String> = dir.keys().collect();
                                keys.sort();

                                for name in keys {
                                    match &dir[name] {
                                        VfsNode::Directory(_) => println!("  [DIR]  {}", name),
                                        VfsNode::File(meta) => println!("  {:>6}B {}", meta.size, name),
                                    }
                                }
                            }
                        } else {
                            println!("Error: Current directory state is corrupt.");
                        }
                    }
                    "cd" => {
                        if arg.is_empty() || arg == "/" {
                            current_path.clear(); // Return to root
                        } else if arg == ".." {
                            current_path.pop(); // Go up one level
                        } else {
                            // Test if the target directory actually exists
                            let mut test_path = current_path.clone();
                            test_path.push(arg.to_string());
                            
                            if vault.get_directory(&test_path).is_some() {
                                current_path = test_path; // Apply the navigation
                            } else {
                                println!("cd: no such directory: {}", arg);
                            }
                        }
                    }
                    _ => {
                        println!("Unknown command: '{}'. Type 'help' for options.", cmd);
                    }
                }
            },
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("\nLocking vault and exiting...");
                break;
            },
            Err(err) => {
                println!("Shell error: {:?}", err);
                break;
            }
        }
    }
    
    Ok(())
}
