use std::io;
use std::path::PathBuf;
use std::process::{Child, Command};

/// Spawns an external viewer inside a highly restricted bubblewrap sandbox.
/// 
/// - `--unshare-all`: Drops all network, IPC, and mount namespaces.
/// - `--unshare-pid`: Creates a new PID namespace (cannot see host processes).
/// - `--ro-bind /usr /usr`: Mounts the host's programs and libraries as Read-Only.
/// - `--tmpfs /tmp`: Creates a temporary, in-memory volatile storage.
pub fn spawn_isolated(file_path: PathBuf) -> io::Result<Child> {
    if !file_path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "Decrypted file not found"));
    }

    // For demonstration, we'll use a standard lightweight PDF viewer like Zathura or Evince.
    // In a real app, this might be configurable by the user.
    let viewer_binary = "zathura"; 

    // Extract the filename so we can map it neatly into the sandbox's /tmp directory
    let file_name = file_path.file_name().unwrap_or_default();
    let sandbox_target_path = PathBuf::from("/tmp").join(file_name);

    let mut cmd = Command::new("bwrap");

    cmd.arg("--unshare-all")
       .arg("--unshare-pid")
       // Provide read-only access to system binaries and libraries
       .arg("--ro-bind").arg("/usr").arg("/usr")
       // Merged /usr symlinks required by modern Linux distributions (like Secureblue)
       .arg("--symlink").arg("usr/lib").arg("/lib")
       .arg("--symlink").arg("usr/lib64").arg("/lib64")
       .arg("--symlink").arg("usr/bin").arg("/bin")
       .arg("--symlink").arg("usr/sbin").arg("/sbin")
       // Create an empty, volatile /tmp directory
       .arg("--tmpfs").arg("/tmp")
       // Inject OUR specific file into the sandbox's /tmp directory as Read-Only
       .arg("--ro-bind").arg(&file_path).arg(&sandbox_target_path)
       // Execute the viewer, pointing it to the sandboxed path
       .arg(viewer_binary)
       .arg(&sandbox_target_path);

    // Spawn the process asynchronously
    cmd.spawn()
}

// -----------------------------------------------------------------------------
// TESTS
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_bwrap_prevents_home_access() {
        // We set up the exact same sandbox parameters, but instead of launching
        // a PDF viewer, we attempt to execute a malicious shell command.
        let status = Command::new("bwrap")
            .arg("--unshare-all")
            .arg("--unshare-pid")
            .arg("--ro-bind").arg("/usr").arg("/usr")
            .arg("--symlink").arg("usr/lib").arg("/lib")
            .arg("--symlink").arg("usr/lib64").arg("/lib64")
            .arg("--symlink").arg("usr/bin").arg("/bin")
            .arg("--tmpfs").arg("/tmp")
            // Malicious payload: attempt to write a file to the host's /home directory
            .arg("sh").arg("-c").arg("touch /home/hacked.txt")
            .status()
            .expect("Failed to execute bwrap. Is bubblewrap installed?");

        // Verification: The command MUST fail. 
        // Because we didn't explicitly bind `/home`, the sandbox sees an empty void.
        // `sh` will return an error because the directory /home does not exist in the sandbox.
        assert!(
            !status.success(), 
            "SECURITY FAILURE: Sandbox allowed execution writing to /home!"
        );
    }
}
