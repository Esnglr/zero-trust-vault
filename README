# 🛡️ Atom: The Zero-Trust Encrypted Vault

Atom is a highly secure, zero-trust virtual filesystem (VFS) and command-line interface built entirely in Rust. It is designed to protect your most sensitive data using state-of-the-art authenticated encryption, mathematical tamper-proofing, and strict application sandboxing.

Unlike traditional encryption tools that leak metadata (like Cryptomator) or waste massive amounts of disk space (like VeraCrypt), Atom creates dynamically sized `.aegis` containers that grow only as you add data, while completely masking the internal directory structure from the host operating system.

## ✨ Core Features

### 🔒 Cryptography & Integrity
* **AES-256-GCM Encryption:** Every file payload and the virtual directory index (FAT) are strictly authenticated and encrypted.
* **Merkle Tree Tamper Detection:** Files are chunked into 4KB blocks and hashed into a Merkle Tree. Atom instantly detects bit-rot, disk corruption, or malicious tampering down to a single byte without needing to decrypt the entire file.
* **Argon2/SHA-256 Key Derivation:** Master keys are securely derived from user passwords, protecting against brute-force attacks.

### 🛡️ Zero-Trust Sandboxing
* **Bubblewrap (`bwrap`) Integration:** The host OS is assumed to be compromised. When viewing or executing files from the vault, Atom wraps the target application (like a PDF viewer) in a strict Linux namespace sandbox. It drops network access, unshares PIDs, and creates volatile in-memory `/tmp` spaces, completely blocking malicious vault files from touching your `/home` directory.

### 💻 Interactive Shell
* **Built-in REPL:** Atom includes a custom command-line shell interface. Once a vault is unlocked, you can navigate your encrypted virtual directory seamlessly using standard commands like `ls` and `cd`.

---

## 🚀 Upcoming Features (The P2P Epic)

Atom is currently evolving from a local encryption tool into a secure, decentralized collaboration platform. The following features are actively in development:

* **Magic Wormhole P2P Sharing:** Establish secure, end-to-end encrypted TCP sessions with friends using short, human-readable passwords (via the SPAKE2 protocol).
* **Tor Anonymity via Arti:** Network traffic will be routed through the Tor network using the bundled Rust `arti` crate, completely hiding the IP addresses of both the sender and receiver.
* **Incremental Delta Syncing:** Why send a 10GB vault if you only added a 2MB photo? By leveraging our Merkle Tree architecture, Atom will isolate the exact 4KB blocks that changed and transmit *only* the difference over the network.
* **Persistent Friend Lists:** Save trusted public keys locally to bypass the one-time short passwords, enabling seamless, authenticated push/pull requests between known devices.

---

## 📦 Installation

To install Atom natively onto your system, clone this repository and use Cargo:
```bash
cd zero-trust-vault
cargo test --release
cargo build --release
cargo install --path .
```

Ensure `~/.cargo/bin` is added to your system `$PATH`.

---

## 🛠️ Usage

**Create a new vault:**
```bash
# Interactive mode (hides password input)
atom create

# Or via flags for automation
atom create --name top_secret --password supersecure123
```

**Open a vault in the interactive shell:**
```bash
atom shell top_secret.aegis
```

Inside the interactive shell:
```text
atom:/ > ls
  [DIR]  docs
       42B readme.txt
atom:/ > cd docs
atom:/docs > exit
```

---

## 🏗️ Architecture: The `.aegis` Format

1. **Header:** Contains the `AEGISVFS` magic bytes and the size of the encrypted directory index.
2. **Encrypted Index (FAT):** A serialized, AES-GCM encrypted payload containing the virtual file hierarchy, file metadata, and the root hashes of the Merkle Trees.
3. **Encrypted Payload Blocks:** Files are broken into 4KB blocks, independently encrypted, and appended to the end of the container.
