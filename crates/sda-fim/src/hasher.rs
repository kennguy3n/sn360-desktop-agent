//! File hashing using SHA-256.
//!
//! Reads files in 8 KB chunks to avoid loading large files entirely into
//! memory.  Designed to be called via `tokio::task::spawn_blocking` since
//! it performs blocking file I/O.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Size of the read buffer used when hashing files (8 KB).
const HASH_BUF_SIZE: usize = 8 * 1024;

/// Read a file in 8 KB chunks and return its hex-encoded SHA-256 hash.
///
/// This function performs blocking I/O and should be called from
/// a blocking context (e.g., `tokio::task::spawn_blocking`).
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open {}: {}", path.display(), e))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_BUF_SIZE];

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_known_content() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"hello world").unwrap();
        f.flush().unwrap();

        let hash = hash_file(f.path()).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_empty_file() {
        let f = NamedTempFile::new().unwrap();
        let hash = hash_file(f.path()).unwrap();
        // SHA-256 of empty input
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_nonexistent_file() {
        let result = hash_file(Path::new("/nonexistent/file/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_large_file() {
        let mut f = NamedTempFile::new().unwrap();
        // Write 1 MB of data (more than a single 8 KB buffer).
        let chunk = vec![0xABu8; 1024];
        for _ in 0..1024 {
            f.write_all(&chunk).unwrap();
        }
        f.flush().unwrap();

        let hash = hash_file(f.path()).unwrap();
        // Verify it returns a valid 64-char hex string.
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify deterministic: hashing again yields the same result.
        let hash2 = hash_file(f.path()).unwrap();
        assert_eq!(hash, hash2);
    }
}
