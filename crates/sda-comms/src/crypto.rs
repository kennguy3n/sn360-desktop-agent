//! Wazuh protocol encryption.
//!
//! Supports Blowfish-CBC (default for Wazuh ≤ 4.x) and AES-256-CBC
//! (when the manager is configured with `<crypto_method>aes</crypto_method>`).
//!
//! Key derivation follows the Wazuh `OS_AddKey` function in `keys.c`:
//!   1. `filesum1 = MD5(name)`
//!   2. `filesum2 = MD5(id)`
//!   3. `combined = filesum1 + filesum2`  (64 hex chars)
//!   4. `filesum1 = MD5(combined)`, then truncated to 15 chars
//!   5. `filesum2 = MD5(key)`
//!   6. `encryption_key = filesum2 + filesum1`  (32 + 15 = 47 chars)
//!
//! Message framing (applied before encryption) follows `CreateSecMSG` in `msgs.c`:
//!   1. Build inner:  `{%05hu rand}{%010u global}:{%04u local}:{message}`
//!   2. Compute MD5 of inner, prepend: `{32-char md5}{inner}`
//!   3. zlib-compress the result
//!   4. Pad with `!` to 8-byte alignment (for Blowfish block size)
//!   5. Encrypt with Blowfish-CBC (zero IV) or AES-256-CBC

use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use md5::{Digest as Md5Digest, Md5};
use ring::rand::SecureRandom;
use tracing::debug;

use crate::blowfish_wazuh::{bf_cbc_decrypt, bf_cbc_encrypt, Blowfish};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Errors from crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid key length")]
    InvalidKeyLength,
    /// Decryption produced an empty payload. This happens when the
    /// peer sends a legitimate keep-open frame with no body and is
    /// not a real error, so callers should distinguish it from
    /// `DecryptionFailed`.
    #[error("empty decrypted payload")]
    EmptyPayload,
}

/// Which block cipher to use for the Wazuh secure channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CryptoMethod {
    /// Blowfish-CBC with static zero IV (Wazuh default).
    #[default]
    Blowfish,
    /// AES-256-CBC with random IV prepended to ciphertext.
    Aes,
}

/// Wazuh protocol cipher.
///
/// Handles key derivation, message framing, and encryption/decryption
/// compatible with a real Wazuh 4.x manager.
pub struct WazuhCipher {
    method: CryptoMethod,
    /// Encryption key string (47 chars, matching Wazuh OS_AddKey output).
    #[allow(dead_code)]
    encryption_key: Vec<u8>,
    /// AES-256 key (first 32 bytes of encryption_key, zero-padded).
    aes_key: [u8; 32],
    /// Blowfish cipher instance (precomputed from the full encryption_key).
    blowfish: Blowfish,
    /// Global message counter.
    global_counter: AtomicU32,
    /// Local message counter (resets at 9997).
    local_counter: AtomicU32,
}

impl WazuhCipher {
    /// Create a new cipher from the four agent key fields.
    ///
    /// Key derivation follows Wazuh's `OS_AddKey` in `keys.c`:
    /// 1. `filesum1 = MD5(name)`
    /// 2. `filesum2 = MD5(id)`
    /// 3. `combined = filesum1 + filesum2` (64 hex chars)
    /// 4. `filesum1 = MD5(combined)` then truncated to 15 chars
    /// 5. `filesum2 = MD5(key)`
    /// 6. `encryption_key = filesum2 + filesum1[0..15]` (47 chars)
    pub fn new(id: &str, name: &str, _ip: &str, key: &str, method: CryptoMethod) -> Self {
        let filesum1 = hex_md5(name.as_bytes());
        let filesum2 = hex_md5(id.as_bytes());

        let combined = format!("{}{}", filesum1, filesum2);
        let mut filesum1 = hex_md5(combined.as_bytes());
        filesum1.truncate(15);

        let filesum2 = hex_md5(key.as_bytes());

        let encryption_key_str = format!("{}{}", filesum2, filesum1);
        let encryption_key = encryption_key_str.as_bytes().to_vec();

        debug!(
            key_len = encryption_key.len(),
            method = ?method,
            "derived Wazuh cipher key"
        );

        let blowfish = Blowfish::new(&encryption_key);

        let mut aes_key = [0u8; 32];
        let copy_len = encryption_key.len().min(32);
        aes_key[..copy_len].copy_from_slice(&encryption_key[..copy_len]);

        Self {
            method,
            encryption_key,
            aes_key,
            blowfish,
            global_counter: AtomicU32::new(0),
            local_counter: AtomicU32::new(0),
        }
    }

    /// Encrypt a plaintext message with Wazuh framing.
    ///
    /// Follows `CreateSecMSG` from Wazuh `msgs.c`:
    /// 1. Build: `{5-digit rand}{10-digit global}:{4-digit local}:{message}`
    /// 2. MD5 the above, prepend the 32-char digest
    /// 3. zlib compress
    /// 4. Pad with `!` for 8-byte block alignment
    /// 5. Encrypt
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let inner = self.build_inner_frame(plaintext);

        let md5_hex = hex_md5(&inner);
        let mut checksummed = Vec::with_capacity(32 + inner.len());
        checksummed.extend_from_slice(md5_hex.as_bytes());
        checksummed.extend_from_slice(&inner);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&checksummed)
            .map_err(|e| CryptoError::EncryptionFailed(format!("compression failed: {e}")))?;
        let compressed = encoder
            .finish()
            .map_err(|e| CryptoError::EncryptionFailed(format!("compression finish: {e}")))?;

        // Match Wazuh CreateSecMSG padding logic exactly:
        // cmp_size = compressed.len() + 1  (the C code does cmp_size++ after compress)
        // bfsize = 8 - (cmp_size % 8), if bfsize == 8 then bfsize = 0
        // Encrypted region starts at _tmpmsg[7 - bfsize], giving (bfsize + 1) '!' bytes
        // Total encrypted = cmp_size + bfsize (always multiple of 8)
        let cmp_size = compressed.len() + 1;
        let bfsize = {
            let rem = cmp_size % 8;
            if rem == 0 {
                0
            } else {
                8 - rem
            }
        };
        let num_padding = bfsize + 1; // always at least 1 '!' byte
        let total = num_padding + compressed.len(); // = cmp_size + bfsize

        let mut padded = Vec::with_capacity(total);
        padded.extend(std::iter::repeat_n(b'!', num_padding));
        padded.extend_from_slice(&compressed);

        let ciphertext = match self.method {
            CryptoMethod::Blowfish => bf_cbc_encrypt(&self.blowfish, &padded),
            CryptoMethod::Aes => self.aes_encrypt(&padded)?,
        };

        debug!(
            plaintext_len = plaintext.len(),
            inner_len = inner.len(),
            compressed_len = compressed.len(),
            ciphertext_len = ciphertext.len(),
            method = ?self.method,
            "encrypted message"
        );

        Ok(ciphertext)
    }

    /// Decrypt a ciphertext message and strip the Wazuh framing.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let decrypted = match self.method {
            CryptoMethod::Blowfish => bf_cbc_decrypt(&self.blowfish, data),
            CryptoMethod::Aes => self.aes_decrypt(data)?,
        };

        if decrypted.is_empty() {
            return Err(CryptoError::EmptyPayload);
        }

        if decrypted[0] == b'!' {
            self.decrypt_compressed(&decrypted)
        } else if decrypted[0] == b':' {
            self.decrypt_old_format(&decrypted)
        } else {
            Err(CryptoError::DecryptionFailed(format!(
                "unexpected first byte after decryption: 0x{:02x}",
                decrypted[0]
            )))
        }
    }

    fn build_inner_frame(&self, message: &[u8]) -> Vec<u8> {
        let rand_val = random_u16();

        let mut local = self.local_counter.fetch_add(1, Ordering::Relaxed) + 1;
        let mut global = self.global_counter.load(Ordering::Relaxed);
        if local >= 9997 {
            self.local_counter.store(0, Ordering::Relaxed);
            local = 0;
            global = self.global_counter.fetch_add(1, Ordering::Relaxed) + 1;
        }

        let header = format!("{:05}{:010}:{:04}:", rand_val, global, local);

        let mut buf = Vec::with_capacity(header.len() + message.len());
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(message);
        buf
    }

    fn decrypt_compressed(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut start = 0;
        while start < data.len() && data[start] == b'!' {
            start += 1;
        }
        let compressed = &data[start..];

        let decompressed = zlib_decompress(compressed)
            .ok_or_else(|| CryptoError::DecryptionFailed("zlib decompression failed".into()))?;

        if decompressed.len() < 53 {
            return Err(CryptoError::DecryptionFailed(
                "decompressed data too short".into(),
            ));
        }

        let (checksum_bytes, rest) = decompressed.split_at(32);
        let expected_checksum = std::str::from_utf8(checksum_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("invalid checksum encoding".into()))?;

        let actual_checksum = hex_md5(rest);
        if actual_checksum != expected_checksum {
            return Err(CryptoError::DecryptionFailed(
                "MD5 checksum mismatch".into(),
            ));
        }

        let rest = &rest[5..];
        let rest = &rest[10..];
        if rest.is_empty() || rest[0] != b':' {
            return Err(CryptoError::DecryptionFailed(
                "missing colon after global counter".into(),
            ));
        }
        let rest = &rest[1..];
        let rest = &rest[4..];
        if rest.is_empty() || rest[0] != b':' {
            return Err(CryptoError::DecryptionFailed(
                "missing colon after local counter".into(),
            ));
        }
        let rest = &rest[1..];

        debug!(
            payload_len = rest.len(),
            method = ?self.method,
            "decrypted compressed message"
        );

        Ok(rest.to_vec())
    }

    fn decrypt_old_format(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let data = strip_trailing_nulls(data);
        let rest = &data[1..];

        if rest.len() < 32 {
            return Err(CryptoError::DecryptionFailed(
                "old format data too short for checksum".into(),
            ));
        }

        let (checksum_bytes, after_checksum) = rest.split_at(32);
        let expected_checksum = std::str::from_utf8(checksum_bytes)
            .map_err(|_| CryptoError::DecryptionFailed("invalid checksum encoding".into()))?;

        let actual_checksum = hex_md5(after_checksum);
        if actual_checksum != expected_checksum {
            return Err(CryptoError::DecryptionFailed(
                "MD5 checksum mismatch (old format)".into(),
            ));
        }

        if after_checksum.len() < 16 {
            return Err(CryptoError::DecryptionFailed(
                "old format too short for counters".into(),
            ));
        }
        let rest = &after_checksum[16..];

        let sep = rest
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| CryptoError::DecryptionFailed("no separator in old format".into()))?;

        Ok(rest[sep + 1..].to_vec())
    }

    fn aes_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let iv = generate_iv_16();
        let cipher = Aes256CbcEnc::new(&self.aes_key.into(), &iv.into());

        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let ct = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| CryptoError::EncryptionFailed("AES padding error".into()))?;

        let mut result = Vec::with_capacity(16 + ct.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(ct);
        Ok(result)
    }

    fn aes_decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 32 {
            return Err(CryptoError::DecryptionFailed(
                "data too short (need IV + 1 block)".into(),
            ));
        }
        let (iv_bytes, ct) = data.split_at(16);
        let iv: [u8; 16] = iv_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionFailed("invalid IV length".into()))?;

        let cipher = Aes256CbcDec::new(&self.aes_key.into(), &iv.into());
        let mut buf = ct.to_vec();
        let pt = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| CryptoError::DecryptionFailed("AES unpadding error".into()))?;
        Ok(pt.to_vec())
    }

    /// Return the crypto method token for the wire prefix.
    pub fn crypto_token(&self) -> &'static str {
        match self.method {
            CryptoMethod::Blowfish => ":",
            CryptoMethod::Aes => "#AES:",
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute MD5 and return the lowercase hex digest (32 chars).
fn hex_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn random_u16() -> u16 {
    let mut buf = [0u8; 2];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .expect("system RNG failed");
    u16::from_ne_bytes(buf)
}

fn generate_iv_16() -> [u8; 16] {
    let mut iv = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut iv)
        .expect("system RNG failed");
    iv
}

fn strip_trailing_nulls(data: &[u8]) -> &[u8] {
    let end = data.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &data[..end]
}

fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).ok()?;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_matches_wazuh() {
        let cipher = WazuhCipher::new(
            "001",
            "agent1",
            "any",
            "secretkey123",
            CryptoMethod::Blowfish,
        );
        assert_eq!(cipher.encryption_key.len(), 47);

        let fs1 = hex_md5(b"agent1");
        let fs2 = hex_md5(b"001");
        let combined = format!("{}{}", fs1, fs2);
        let mut fs1_new = hex_md5(combined.as_bytes());
        fs1_new.truncate(15);
        let fs2_new = hex_md5(b"secretkey123");
        let expected = format!("{}{}", fs2_new, fs1_new);
        assert_eq!(expected.len(), 47);
        assert_eq!(cipher.encryption_key, expected.as_bytes());
    }

    #[test]
    fn test_blowfish_roundtrip() {
        let cipher = WazuhCipher::new(
            "001",
            "myhost",
            "any",
            "abc123def456",
            CryptoMethod::Blowfish,
        );
        let plaintext = b"#!-agent keepalive";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_roundtrip() {
        let cipher = WazuhCipher::new("002", "myhost", "any", "key456", CryptoMethod::Aes);
        let plaintext = b"d:{\"type\":\"event\",\"data\":{}}";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys_fail_blowfish() {
        let cipher1 = WazuhCipher::new("001", "host1", "any", "key1", CryptoMethod::Blowfish);
        let cipher2 = WazuhCipher::new("002", "host2", "any", "key2", CryptoMethod::Blowfish);

        let encrypted = cipher1.encrypt(b"secret data").unwrap();
        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_keys_fail_aes() {
        let cipher1 = WazuhCipher::new("001", "host1", "any", "key1", CryptoMethod::Aes);
        let cipher2 = WazuhCipher::new("002", "host2", "any", "key2", CryptoMethod::Aes);

        let encrypted = cipher1.encrypt(b"secret data").unwrap();
        let result = cipher2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_message_blowfish() {
        let cipher = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Blowfish);
        let plaintext = vec![0x42u8; 65536];
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_message_aes() {
        let cipher = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Aes);
        let plaintext = vec![0x42u8; 65536];
        let encrypted = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_message_framing_format() {
        let cipher = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Blowfish);

        let inner = cipher.build_inner_frame(b"hello");
        let s = String::from_utf8_lossy(&inner);

        assert!(s.len() >= 21 + 5);
        assert!(s.ends_with("hello"));
        assert_eq!(inner[15], b':');
        assert_eq!(inner[20], b':');
    }

    #[test]
    fn test_crypto_token() {
        let bf = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Blowfish);
        assert_eq!(bf.crypto_token(), ":");

        let aes = WazuhCipher::new("001", "host", "any", "k", CryptoMethod::Aes);
        assert_eq!(aes.crypto_token(), "#AES:");
    }

    #[test]
    fn test_strip_trailing_nulls() {
        assert_eq!(strip_trailing_nulls(b"hello\0\0\0"), b"hello");
        assert_eq!(strip_trailing_nulls(b"hello"), b"hello");
        assert_eq!(strip_trailing_nulls(b"\0\0"), b"" as &[u8]);
    }
}
