use clap::{Parser, Subcommand};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::io::{self, Write};
use std::path::PathBuf;

// Import our custom modules
use zero_trust_vault::crypto::kdf::derive_key_from_password;
use zero_trust_vault::vfs::{VfsContainer, VfsNode};

/// Atom: A Zero-Trust Encrypted Vault
#[derive(Parser)]
#[command(name = "atom")]
#[command(about = "A highly secure, zero-trust virtual filesystem", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new encrypted vault
    Create {
        /// The name of the vault (will append .aegis)
        #[arg(short, long)]
        name: Option<String>,

        /// The master password for the vault
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Open an interactive shell for an existing vault
    Shell {
        /// The path to the .aegis vault file
        vault_file: PathBuf,
    },
}

fn main() -> rustyline::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Create { name, password } => {
            // 1. Resolve the vault name (use flag or prompt user)
            let final_name = match name {
                Some(n) => n.clone(),
                None => {
                    print!("Enter new vault name: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if final_name.is_empty() {
                eprintln!("❌ Error: Vault name cannot be empty.");
                std::process::exit(1);
            }

            // 2. Resolve the password with a verification loop
            let final_password = match password {
                Some(p) => p.clone(),
                None => {
                    loop {
                        let p1 = rpassword::prompt_password("Enter master password: ").unwrap();
                        let p2 = rpassword::prompt_password("Verify master password: ").unwrap();

                        if p1 != p2 {
                            eprintln!("❌ Passwords do not match. Please try again.\n");
                            continue;
                        }

                        if p1.is_empty() {
                            eprintln!("❌ Error: Password cannot be empty.\n");
                            continue;
                        }

                        // If we reach here, passwords match and are not empty
                        break p1;
                    }
                }
            };

            // Catch-all in case they passed an empty string via the CLI flag (e.g., --password "")
            if final_password.is_empty() {
                eprintln!("❌ Error: Password cannot be empty.");
                std::process::exit(1);
            }

            let file_name = format!("{}.aegis", final_name);
            let master_key = derive_key_from_password(&final_password);

            println!("Creating new zero-trust vault: {}", file_name);

            match VfsContainer::init(&file_name, &master_key) {
                Ok(_) => println!("✅ Vault created successfully. You can now open it with `atom shell {}`", file_name),
                Err(e) => eprintln!("❌ Failed to create vault: {}", e),
            }
        }
        Commands::Shell { vault_file } => {
            // Securely prompt for the password using rpassword instead of standard I/O
            let password = rpassword::prompt_password("Enter vault password: ").unwrap();
            let master_key = derive_key_from_password(&password);

            println!("Decrypting and verifying vault integrity...");
            
            match VfsContainer::load(vault_file, &master_key) {
                Ok(vault) => {
                    println!("✅ Vault unlocked successfully.\n");
                    run_interactive_shell(vault)?;
                }
                Err(e) => {
                    eprintln!("❌ Access Denied: Invalid password or corrupted vault file.");
                    eprintln!("Error details: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// The REPL (Read-Eval-Print Loop) for interacting with the unlocked vault
fn run_interactive_shell(vault: VfsContainer) -> rustyline::Result<()> {
    let mut rl = DefaultEditor::new()?;
    let mut current_path: Vec<String> = Vec::new();

    println!("========================================");
    println!("🛡️  Zero-Trust Vault Interactive Shell");
    println!("Type 'help' for commands, 'exit' to lock");
    println!("========================================");

    loop {
        let display_path = if current_path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", current_path.join("/"))
        };
        
        let prompt = format!("atom:{} > ", display_path);

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() { continue; }
                rl.add_history_entry(line)?;

                let mut parts = line.split_whitespace();
                let cmd = parts.next().unwrap_or("");
                let arg = parts.next().unwrap_or("");

                match cmd {
                    "exit" | "quit" => {
                        println!("Wiping memory, locking vault, and exiting...");
                        break;
                    }
                    "help" => {
                        println!("Available commands:");
                        println!("  ls        - List contents of the current directory");
                        println!("  cd <dir>  - Change directory");
                        println!("  exit      - Safely lock and close the vault");
                    }
                    "ls" => {
                        if let Some(dir) = vault.get_directory(&current_path) {
                            if dir.is_empty() {
                                println!("  (empty)");
                            } else {
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
                            current_path.clear();
                        } else if arg == ".." {
                            current_path.pop();
                        } else {
                            let mut test_path = current_path.clone();
                            test_path.push(arg.to_string());
                            
                            if vault.get_directory(&test_path).is_some() {
                                current_path = test_path;
                            } else {
                                println!("cd: no such directory: {}", arg);
                            }
                        }
                    }
                    _ => println!("Unknown command: '{}'. Type 'help' for options.", cmd),
                }
            },
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("\nWiping memory, locking vault, and exiting...");
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
