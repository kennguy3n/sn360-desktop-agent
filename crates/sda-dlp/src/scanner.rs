//! DLP byte-slice scanner.
//!
//! The [`Scanner`] holds a compiled set of [`crate::patterns::PatternDef`]
//! values and exposes [`Scanner::scan`] which returns a list of
//! [`DlpFinding`] structs for the input buffer.
//!
//! # Redaction invariant
//!
//! `docs/architecture.md` § 8.2 says **no matched bytes may leave the
//! scanner**. Every [`DlpFinding`] therefore carries only:
//!
//! - the matching category (e.g. `"pii.ssn"`)
//! - the byte offset and length of the match within the input
//! - a Blake3 hash of a 32-byte window around the match (16 bytes
//!   before + 16 bytes of context after) for fingerprinting in the
//!   control plane.
//!
//! Tests in this crate assert that the `Debug` and `serde` round-
//! trip of [`DlpFinding`] never contains the source bytes.

use serde::{Deserialize, Serialize};

use crate::patterns::PatternDef;

/// Half-window size used by the surrounding-bytes Blake3 hash.
/// Total window is 32 bytes (16 + 16). Kept small so that two
/// adjacent matches that share neighbouring bytes still get
/// distinguishable fingerprints.
pub const FINGERPRINT_WINDOW_HALF: usize = 16;

/// A DLP scanner finding. Carries enough metadata to reconstruct
/// what happened upstream **without** ever including the matched
/// bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpFinding {
    /// Stable category, e.g. `"pii.ssn"`.
    pub category: String,
    /// Display name, e.g. `"US Social Security Number"`.
    pub pattern_name: String,
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// Length of the match, in bytes.
    pub length: usize,
    /// Lowercase hex Blake3 fingerprint of the 32-byte window
    /// around the match.
    pub fingerprint: String,
}

/// Compiled multi-pattern scanner.
pub struct Scanner {
    patterns: Vec<PatternDef>,
}

impl Scanner {
    /// Build a scanner from the supplied pattern set.
    pub fn new(patterns: Vec<PatternDef>) -> Self {
        Self { patterns }
    }

    /// Number of active patterns. Mostly useful for assertions.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Scan an arbitrary byte buffer.
    ///
    /// This is the canonical entry point. Offsets and fingerprints
    /// returned in each [`DlpFinding`] index directly into `input`,
    /// so the caller can recover the source bytes (e.g. to extend
    /// a fingerprint window) without translating positions.
    ///
    /// The scanner uses [`regex::bytes`] so non-UTF-8 input is
    /// passed through verbatim — no lossy reconstruction is needed
    /// and no offset skew can result from replacement characters.
    pub fn scan_bytes(&self, input: &[u8]) -> Vec<DlpFinding> {
        let mut out = Vec::new();
        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(input) {
                let candidate = mat.as_bytes();
                if !pattern.validate(candidate) {
                    continue;
                }
                let fingerprint = fingerprint_window(input, mat.start(), mat.end());
                out.push(DlpFinding {
                    category: pattern.category.to_string(),
                    pattern_name: pattern.name.to_string(),
                    offset: mat.start(),
                    length: mat.end() - mat.start(),
                    fingerprint,
                });
            }
        }
        out
    }

    /// Convenience wrapper around [`Scanner::scan_bytes`] that
    /// takes a `&str`. Offsets remain byte offsets (matching
    /// `str::as_bytes` indexing), which is what every caller in
    /// this crate expects.
    pub fn scan(&self, input: &str) -> Vec<DlpFinding> {
        self.scan_bytes(input.as_bytes())
    }
}

/// Compute the Blake3 fingerprint of a 32-byte window centred on
/// `[start, end)`. The window is clamped to the buffer bounds; in
/// the unlikely case the buffer is empty, the digest is computed
/// over an empty slice (Blake3's documented zero-length digest).
pub fn fingerprint_window(buf: &[u8], start: usize, end: usize) -> String {
    let lo = start.saturating_sub(FINGERPRINT_WINDOW_HALF);
    let hi = end.saturating_add(FINGERPRINT_WINDOW_HALF).min(buf.len());
    let slice = if lo <= hi { &buf[lo..hi] } else { &[][..] };
    blake3::hash(slice).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::baseline_patterns;

    fn scanner() -> Scanner {
        Scanner::new(baseline_patterns())
    }

    #[test]
    fn finds_a_synthetic_ssn() {
        let input = "patient: 123-45-6789, dob: 1990-01-01";
        let findings = scanner().scan(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "pii.ssn");
        assert_eq!(findings[0].length, 11);
        // Redaction invariant: serialised finding must NOT contain
        // the matched bytes.
        let json = serde_json::to_string(&findings[0]).unwrap();
        assert!(!json.contains("123-45-6789"), "finding leaked SSN: {json}");
        // The Debug repr must also be safe.
        let dbg = format!("{:?}", findings[0]);
        assert!(!dbg.contains("123-45-6789"), "Debug leaked: {dbg}");
    }

    #[test]
    fn finds_a_synthetic_uk_ni() {
        let input = "NI: AB123456C end";
        let findings = scanner().scan(input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "pii.uk_ni");
        assert_eq!(findings[0].length, 9);
        let json = serde_json::to_string(&findings[0]).unwrap();
        assert!(!json.contains("AB123456C"));
    }

    #[test]
    fn finds_a_real_luhn_pan() {
        let input = "card: 4242424242424242 expiry";
        let findings = scanner().scan(input);
        let pan = findings
            .iter()
            .find(|f| f.category == "pci.pan_luhn")
            .expect("expected PAN match");
        assert_eq!(pan.length, 16);
        let json = serde_json::to_string(pan).unwrap();
        assert!(!json.contains("4242424242424242"));
    }

    #[test]
    fn ignores_invalid_luhn_pan() {
        let input = "card: 1234567890123";
        assert!(
            !scanner()
                .scan(input)
                .iter()
                .any(|f| f.category == "pci.pan_luhn"),
            "expected no PAN match"
        );
    }

    #[test]
    fn clean_text_produces_no_findings() {
        let input = "This is a regular document with no PII or PCI in it.";
        assert!(scanner().scan(input).is_empty());
    }

    #[test]
    fn fingerprint_is_stable_for_identical_windows() {
        let buf = b"prefix-data-123-45-6789-suffix";
        let f1 = fingerprint_window(buf, 12, 23);
        let f2 = fingerprint_window(buf, 12, 23);
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 64);
    }

    #[test]
    fn fingerprint_differs_when_window_differs() {
        let buf = b"prefix-data-123-45-6789-suffix";
        let f1 = fingerprint_window(buf, 0, 5);
        let f2 = fingerprint_window(buf, 12, 23);
        assert_ne!(f1, f2);
    }

    #[test]
    fn scan_bytes_handles_invalid_utf8() {
        let mut buf = b"ssn: 123-45-6789 \xff\xfe end".to_vec();
        buf.extend_from_slice(b"trailing");
        let findings = scanner().scan_bytes(&buf);
        assert!(findings.iter().any(|f| f.category == "pii.ssn"));
    }
}
