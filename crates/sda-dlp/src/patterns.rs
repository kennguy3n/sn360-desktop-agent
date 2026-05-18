//! Built-in DLP regex pattern set.
//!
//! Three baseline detectors ship with the agent:
//!
//! | Pattern        | Category       | Notes                                |
//! |----------------|----------------|--------------------------------------|
//! | `pii.ssn`      | US SSN         | Hyphenated `\d{3}-\d{2}-\d{4}`       |
//! | `pii.uk_ni`    | UK NI Number   | `[A-Z]{2}\d{6}[A-Z]`, group-2 valid  |
//! | `pci.pan_luhn` | PCI PAN + Luhn | 13–19 digits w/ valid Luhn checksum  |
//!
//! The control-plane TRDS service can ship additional patterns at
//! runtime; that path is implemented by [`crate::scanner::Scanner`]
//! which keeps a pluggable rule list, so the built-ins here are
//! just the defaults.
//!
//! ## Why these three
//!
//! The baseline is chosen to demonstrate three orthogonal
//! validation strategies inside the same pattern set:
//!
//! - SSN: pure regex (anchored by `\b` so longer digit runs don't
//!   trigger false positives).
//! - UK NI: regex + structural constraint (the leading two letters
//!   may not be one of the disallowed prefixes).
//! - PCI PAN: regex pre-filter (13–19 digits) + Luhn validator.
//!
//! Anyone adding a fourth pattern should follow the same shape:
//! a regex narrows the candidate set and a `validator` closure
//! confirms semantic correctness. The redaction invariant
//! (no matched content escapes the scanner) is enforced by the
//! scanner, not the pattern, so [`PatternDef`] does not need to
//! mention bytes.
//!
//! ## Byte-oriented matching
//!
//! All patterns operate on `&[u8]` via the [`regex::bytes`] engine.
//! The DLP scanner inspects raw file contents (which can contain
//! arbitrary bytes, not just valid UTF-8), and we need byte
//! offsets that index into the original buffer — not into a lossy
//! UTF-8 reconstruction. The three baseline regexes only ever
//! match ASCII bytes (digits, hyphens, ASCII letters), so the
//! validators safely treat the captured slice as ASCII.

use regex::bytes::Regex;

/// A single DLP pattern definition.
pub struct PatternDef {
    /// Stable category identifier, e.g. `"pii.ssn"`.
    pub category: &'static str,
    /// Human-readable name surfaced in wired findings.
    pub name: &'static str,
    /// Compiled byte-oriented regular expression used to find
    /// candidate matches in a raw buffer.
    pub regex: Regex,
    /// Optional structural validator. Returns `true` when the byte
    /// slice from the regex match is a real match. Used to reject
    /// false positives that the regex alone cannot eliminate
    /// (e.g. invalid PAN checksums). The slice is guaranteed to
    /// contain only ASCII bytes because the baseline regexes reject
    /// non-ASCII input.
    pub validator: fn(&[u8]) -> bool,
}

impl PatternDef {
    /// True when `candidate` (a slice already extracted by
    /// [`Self::regex`]) survives the structural validator.
    pub fn validate(&self, candidate: &[u8]) -> bool {
        (self.validator)(candidate)
    }
}

/// Build the baseline pattern set. The function is cheap and
/// deterministic, but each call recompiles the regexes — keep one
/// instance around in the [`crate::scanner::Scanner`].
pub fn baseline_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            category: "pii.ssn",
            name: "US Social Security Number",
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex"),
            validator: validate_ssn,
        },
        PatternDef {
            category: "pii.uk_ni",
            name: "UK National Insurance Number",
            regex: Regex::new(r"\b[A-Z]{2}\d{6}[A-Z]\b").expect("uk_ni regex"),
            validator: validate_uk_ni,
        },
        PatternDef {
            category: "pci.pan_luhn",
            name: "Payment Card Number (Luhn)",
            // 13–19 digits is the ISO/IEC 7812 PAN range.
            regex: Regex::new(r"\b\d{13,19}\b").expect("pan regex"),
            validator: validate_pan_luhn,
        },
    ]
}

/// Returns true when `pattern_id` is one of the categories built in
/// to this crate. Used by `DlpConfig::patterns` to drop typos before
/// the scanner is constructed.
pub fn is_builtin_category(pattern_id: &str) -> bool {
    matches!(pattern_id, "pii.ssn" | "pii.uk_ni" | "pci.pan_luhn")
}

/// Build a pattern set restricted to `selected` categories.
///
/// Unknown / typo'd categories are silently dropped so a bad config
/// can't take down the module. The caller (`DlpModule::start`) logs
/// a warning when this happens.
pub fn select(selected: &[String]) -> Vec<PatternDef> {
    let all = baseline_patterns();
    if selected.is_empty() {
        return all;
    }
    all.into_iter()
        .filter(|p| selected.iter().any(|s| s == p.category))
        .collect()
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Parse a fixed-length ASCII decimal slice into a `u32`. Returns
/// `None` if any byte is not an ASCII digit. Used by the SSN
/// validator so we never round-trip the matched bytes through a
/// `String` for arithmetic.
fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(acc)
}

/// Loose SSN validator. Real SSA-issued numbers exclude `000`,
/// `666`, and `900–999` in the area block; we encode those
/// constraints so synthetic fixtures of the form `000-12-3456`
/// don't trigger.
fn validate_ssn(s: &[u8]) -> bool {
    if s.len() != 11 {
        return false;
    }
    if s[3] != b'-' || s[6] != b'-' {
        return false;
    }
    let Some(area) = parse_ascii_u32(&s[0..3]) else {
        return false;
    };
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    let Some(group) = parse_ascii_u32(&s[4..6]) else {
        return false;
    };
    if group == 0 {
        return false;
    }
    let Some(serial) = parse_ascii_u32(&s[7..11]) else {
        return false;
    };
    serial != 0
}

/// UK National Insurance number validator. Disallows the prefixes
/// reserved by HMRC (`BG`, `GB`, `KN`, `NK`, `NT`, `TN`, `ZZ`)
/// plus prefixes that begin with `D`, `F`, `I`, `Q`, `U`, `V`, or
/// contain `O` in either position.
fn validate_uk_ni(s: &[u8]) -> bool {
    if s.len() != 9 {
        return false;
    }
    let p1 = s[0];
    let p2 = s[1];
    if matches!(p1, b'D' | b'F' | b'I' | b'Q' | b'U' | b'V' | b'O') {
        return false;
    }
    if matches!(p2, b'D' | b'F' | b'I' | b'O' | b'Q' | b'U' | b'V') {
        return false;
    }
    let prefix = &s[..2];
    if matches!(
        prefix,
        b"BG" | b"GB" | b"KN" | b"NK" | b"NT" | b"TN" | b"ZZ"
    ) {
        return false;
    }
    let suffix = s[8];
    matches!(suffix, b'A' | b'B' | b'C' | b'D')
}

/// Luhn check over an ASCII digit string. Public so callers writing
/// new PAN-like patterns can reuse it.
///
/// Returns `false` when `digits` is empty — an empty buffer has a
/// `sum` of zero, which `is_multiple_of(10)` would otherwise report
/// as a valid Luhn checksum. The PAN pattern's internal caller
/// (`validate_pan_luhn`) already rejects short inputs before the
/// Luhn step, but this function is `pub` so the empty-input guard
/// belongs here too — flagged by the Devin Review bot on PR #25.
pub fn luhn_check(digits: &[u8]) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &b in digits.iter().rev() {
        if !b.is_ascii_digit() {
            return false;
        }
        let d = (b - b'0') as u32;
        let v = if alt { d * 2 } else { d };
        sum += if v > 9 { v - 9 } else { v };
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

fn validate_pan_luhn(s: &[u8]) -> bool {
    if s.len() < 13 || s.len() > 19 {
        return false;
    }
    luhn_check(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_patterns_have_all_three_categories() {
        let p = baseline_patterns();
        let categories: Vec<_> = p.iter().map(|p| p.category).collect();
        assert!(categories.contains(&"pii.ssn"));
        assert!(categories.contains(&"pii.uk_ni"));
        assert!(categories.contains(&"pci.pan_luhn"));
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn ssn_validator_accepts_valid_numbers() {
        for s in [b"123-45-6789" as &[u8], b"555-12-3456", b"888-55-4321"] {
            assert!(validate_ssn(s), "expected ok: {s:?}");
        }
    }

    #[test]
    fn ssn_validator_rejects_reserved_blocks() {
        for s in [
            b"000-12-3456" as &[u8],
            b"666-12-3456",
            b"900-12-3456",
            b"999-12-3456",
            b"123-00-3456",
            b"123-45-0000",
            b"abc-de-fghi",
        ] {
            assert!(!validate_ssn(s), "expected reject: {s:?}");
        }
    }

    #[test]
    fn uk_ni_validator_accepts_valid_numbers() {
        for s in [b"AB123456C" as &[u8], b"JR987654A", b"MA111111D"] {
            assert!(validate_uk_ni(s), "expected ok: {s:?}");
        }
    }

    #[test]
    fn uk_ni_validator_rejects_reserved_prefixes() {
        for s in [
            b"BG123456A" as &[u8],
            b"GB123456A",
            b"NK123456A",
            b"ZZ123456A",
        ] {
            assert!(!validate_uk_ni(s), "expected reject: {s:?}");
        }
    }

    #[test]
    fn pan_validator_accepts_a_real_luhn_number() {
        // Stripe / Visa public test PAN.
        assert!(validate_pan_luhn(b"4242424242424242"));
        // 13-digit Visa test PAN.
        assert!(validate_pan_luhn(b"4222222222222"));
    }

    #[test]
    fn pan_validator_rejects_invalid_luhn_or_wrong_length() {
        assert!(!validate_pan_luhn(b"1234567890123"));
        assert!(!validate_pan_luhn(b"4242424242424243"));
        assert!(!validate_pan_luhn(b"1"));
        assert!(!validate_pan_luhn(b"12345678901234567890")); // 20 digits
    }

    #[test]
    fn luhn_check_handles_known_values() {
        assert!(luhn_check(b"79927398713"));
        assert!(!luhn_check(b"79927398710"));
        assert!(!luhn_check(b"not digits"));
    }

    #[test]
    fn luhn_check_rejects_empty_input() {
        // The naive implementation returns `true` here because the
        // digit-sum is zero and `0 % 10 == 0`. An empty buffer is
        // never a valid PAN, so the public API guards against it.
        assert!(!luhn_check(b""));
    }

    #[test]
    fn select_filters_to_requested_categories() {
        let only_ssn = select(&["pii.ssn".to_string()]);
        assert_eq!(only_ssn.len(), 1);
        assert_eq!(only_ssn[0].category, "pii.ssn");

        let empty = select(&[]);
        assert_eq!(empty.len(), 3);

        let unknown = select(&["nope.bad".to_string()]);
        assert_eq!(unknown.len(), 0);
    }

    #[test]
    fn is_builtin_category_recognises_baseline() {
        assert!(is_builtin_category("pii.ssn"));
        assert!(is_builtin_category("pci.pan_luhn"));
        assert!(!is_builtin_category("nope"));
    }
}
