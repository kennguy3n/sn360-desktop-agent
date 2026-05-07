//! Download, verify, atomically replace, and (if needed) roll back an
//! agent binary from the signed manifest returned by
//! [`crate::checker::check_for_update`].
//!
//! Verification order is: advertised SHA-256 against the downloaded
//! bytes, then Ed25519 signature over the *same* digest using the
//! operator-pinned verifying key from
//! [`UpdateConfig::public_key`](sda_core::config::UpdateConfig::public_key).
//! Both must succeed before anything touches the installed binary.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

use sda_core::config::UpdateConfig;

use crate::checker::UpdateManifest;

/// Outcome of [`install_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Binary was swapped and the smoke test passed.
    Installed,
    /// Binary was swapped, the smoke test failed, and the previous
    /// binary has been restored from `.bak`.
    RolledBack,
}

/// Download the new binary, verify it, atomically replace the current
/// binary, run a basic smoke test, and roll back on failure.
///
/// The pinned verifying key is expected as a hex-encoded 32-byte
/// Ed25519 public key in [`UpdateConfig::public_key`]. An empty
/// configured key is treated as a misconfiguration and aborts the
/// install — we never swap an unsigned binary into place.
pub async fn install_update(
    cfg: &UpdateConfig,
    manifest: &UpdateManifest,
    current_binary: &Path,
) -> Result<InstallOutcome> {
    if cfg.public_key.trim().is_empty() {
        bail!("updater has no public_key configured — refusing to install unsigned binaries");
    }

    let verifying_key = parse_public_key(&cfg.public_key).context("parsing updater public_key")?;
    let expected_digest = decode_hex_digest(&manifest.sha256)
        .context("decoding expected sha256 digest from manifest")?;
    let signature = decode_signature(&manifest.signature)
        .context("decoding Ed25519 signature from manifest")?;

    // Download into a temp file that lives alongside the current
    // binary so the final rename is an atomic, same-filesystem
    // operation.
    let parent = current_binary
        .parent()
        .ok_or_else(|| anyhow!("current_binary has no parent directory"))?;
    let temp_path = parent.join(format!(".sda-agent.update.{}", std::process::id()));

    let download_result = download_and_verify(
        &manifest.url,
        &temp_path,
        &expected_digest,
        &signature,
        &verifying_key,
    )
    .await;

    if let Err(e) = download_result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    preserve_mode(current_binary, &temp_path).context("preserving file mode on new binary")?;

    // Save a rollback copy before swapping in the new binary.
    let backup_path = backup_path_for(current_binary);
    copy_file(current_binary, &backup_path)
        .with_context(|| format!("creating rollback copy at {}", backup_path.display()))?;

    // Atomic replace (POSIX rename(2); ReplaceFile on NTFS).
    fs::rename(&temp_path, current_binary).context("atomic rename of new binary into place")?;

    info!(
        version = %manifest.version,
        backup = %backup_path.display(),
        "new binary installed; running smoke test"
    );

    let smoke_timeout = Duration::from_secs(cfg.smoke_test_timeout.max(1));
    match run_smoke_test(current_binary, smoke_timeout).await {
        Ok(()) => {
            // Keep the .bak around on disk — operators can reclaim
            // the space manually, and a second failed start will
            // still have something to restore from.
            Ok(InstallOutcome::Installed)
        }
        Err(e) => {
            warn!(
                error = %e,
                "smoke test of new binary failed; rolling back"
            );
            rollback(current_binary, &backup_path).context("rollback after failed smoke test")?;
            Ok(InstallOutcome::RolledBack)
        }
    }
}

/// Stream the URL to `dest`, hash it as we write, and verify hash
/// + signature before returning.
async fn download_and_verify(
    url: &str,
    dest: &Path,
    expected_digest: &[u8; 32],
    signature: &Signature,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .user_agent(concat!("sda-agent-updater/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building reqwest client for download")?;

    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    if !resp.status().is_success() {
        bail!("update download returned status {}", resp.status());
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("creating {}", dest.display()))?;
    let mut hasher = Sha256::new();

    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("reading download chunk")?;
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .context("writing download chunk")?;
    }
    file.flush().await.context("flushing download")?;
    file.sync_all()
        .await
        .context("fsync on downloaded binary")?;
    drop(file);

    let actual_digest = hasher.finalize();
    if actual_digest.as_slice() != expected_digest {
        bail!("downloaded binary SHA-256 mismatch");
    }

    verifying_key
        .verify(expected_digest, signature)
        .map_err(|e| anyhow!("Ed25519 signature verification failed: {e}"))?;

    debug!(
        path = %dest.display(),
        "download verified (sha256 + Ed25519)"
    );
    Ok(())
}

/// Run the freshly-installed binary with `--version` and require it
/// to exit 0 within `timeout`. This is a deliberately minimal health
/// check — if the new binary can't even print its version we know
/// something is badly wrong and it's safer to roll back.
async fn run_smoke_test(binary: &Path, timeout: Duration) -> Result<()> {
    let output = tokio::time::timeout(timeout, Command::new(binary).arg("--version").output())
        .await
        .map_err(|_| anyhow!("smoke test timed out after {:?}", timeout))?
        .with_context(|| format!("spawning {}", binary.display()))?;

    if !output.status.success() {
        bail!(
            "smoke test exit status {:?}: stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Restore `backup` over `current` after a failed install.
pub(crate) fn rollback(current: &Path, backup: &Path) -> Result<()> {
    if !backup.exists() {
        bail!("no rollback copy at {}", backup.display());
    }
    fs::rename(backup, current)
        .with_context(|| format!("restoring {} from {}", current.display(), backup.display()))?;
    Ok(())
}

fn backup_path_for(current: &Path) -> PathBuf {
    let mut s = current.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

#[cfg(unix)]
fn preserve_mode(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(src)?.permissions().mode();
    fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn preserve_mode(_src: &Path, _dst: &Path) -> io::Result<()> {
    // Windows uses ACLs rather than Unix mode bits; the MSI installer
    // applies the correct ACL at install time and rename() preserves
    // the NTFS ACL on the destination path, so there's nothing to do
    // here.
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> io::Result<()> {
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

fn parse_public_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_key.trim()).context("hex-decoding public_key")?;
    let fixed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("public_key must be 32 bytes (got != 32)"))?;
    VerifyingKey::from_bytes(&fixed).context("invalid Ed25519 public key bytes")
}

fn decode_hex_digest(hex_digest: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_digest.trim()).context("hex-decoding sha256")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("sha256 digest must be 32 bytes"))
}

fn decode_signature(hex_sig: &str) -> Result<Signature> {
    let bytes = hex::decode(hex_sig.trim()).context("hex-decoding signature")?;
    let fixed: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&fixed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::TempDir;

    fn make_keypair() -> SigningKey {
        // Fixed seed so failures are reproducible in CI.
        let seed = [7u8; 32];
        SigningKey::from_bytes(&seed)
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn parse_public_key_accepts_hex_encoded_vk() {
        let sk = make_keypair();
        let vk = sk.verifying_key();
        let hex_vk = hex::encode(vk.to_bytes());
        let parsed = parse_public_key(&hex_vk).unwrap();
        assert_eq!(parsed.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn parse_public_key_rejects_wrong_length() {
        let err = parse_public_key("deadbeef").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn decode_signature_rejects_wrong_length() {
        let err = decode_signature("deadbeef").unwrap_err();
        assert!(err.to_string().contains("64 bytes"));
    }

    #[test]
    fn backup_path_appends_bak() {
        let p = Path::new("/usr/bin/sda-agent");
        assert_eq!(backup_path_for(p), PathBuf::from("/usr/bin/sda-agent.bak"));
    }

    #[test]
    fn valid_signature_over_digest_verifies() {
        let sk = make_keypair();
        let vk = sk.verifying_key();

        let payload = b"hello world";
        let digest = sha256_of(payload);
        let sig = sk.sign(&digest);

        // Verifier accepts a matching digest.
        assert!(vk.verify(&digest, &sig).is_ok());

        // And rejects a tampered digest.
        let mut tampered = digest;
        tampered[0] ^= 0xff;
        assert!(vk.verify(&tampered, &sig).is_err());
    }

    #[test]
    fn rollback_restores_previous_binary() {
        let dir = TempDir::new().unwrap();
        let current = dir.path().join("sda-agent");
        let backup = dir.path().join("sda-agent.bak");

        fs::write(&current, b"new-but-broken").unwrap();
        fs::write(&backup, b"old-known-good").unwrap();

        rollback(&current, &backup).unwrap();

        assert_eq!(fs::read(&current).unwrap(), b"old-known-good");
        assert!(!backup.exists(), ".bak should be consumed by rollback");
    }

    #[test]
    fn rollback_errors_when_backup_missing() {
        let dir = TempDir::new().unwrap();
        let current = dir.path().join("sda-agent");
        let backup = dir.path().join("sda-agent.bak");
        fs::write(&current, b"new").unwrap();

        let err = rollback(&current, &backup).unwrap_err();
        assert!(err.to_string().contains("no rollback copy"));
    }

    #[cfg(unix)]
    #[test]
    fn preserve_mode_copies_executable_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"a").unwrap();
        fs::write(&dst, b"b").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o600)).unwrap();

        preserve_mode(&src, &dst).unwrap();

        let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}
