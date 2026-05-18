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

use regex::Regex;

/// A single DLP pattern definition.
pub struct PatternDef {
    /// Stable category identifier, e.g. `"pii.ssn"`.
    pub category: &'static str,
    /// Human-readable name surfaced in wired findings.
    pub name: &'static str,
    /// Compiled regular expression used to find candidate matches.
    pub regex: Regex,
    /// Optional structural validator. Returns `true` when the byte
    /// slice from the regex match is a real match. Used to reject
    /// false positives that the regex alone cannot eliminate
    /// (e.g. invalid PAN checksums).
    pub validator: fn(&str) -> bool,
}

impl PatternDef {
    /// True when `candidate` (a slice already extracted by
    /// [`Self::regex`]) survives the structural validator.
    pub fn validate(&self, candidate: &str) -> bool {
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

/// Loose SSN validator. Real SSA-issued numbers exclude `000`,
/// `666`, and `900–999` in the area block; we encode those
/// constraints so synthetic fixtures of the form `000-12-3456`
/// don't trigger.
fn validate_ssn(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 11 {
        return false;
    }
    if bytes[3] != b'-' || bytes[6] != b'-' {
        return false;
    }
    let area: u32 = match s[0..3].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    let group: u32 = match s[4..6].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if group == 0 {
        return false;
    }
    let serial: u32 = match s[7..11].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    serial != 0
}

/// UK National Insurance number validator. Disallows the prefixes
/// reserved by HMRC (`BG`, `GB`, `KN`, `NK`, `NT`, `TN`, `ZZ`)
/// plus prefixes that begin with `D`, `F`, `I`, `Q`, `U`, `V`, or
/// contain `O` in either position.
fn validate_uk_ni(s: &str) -> bool {
    if s.len() != 9 {
        return false;
    }
    let bytes = s.as_bytes();
    let p1 = bytes[0] as char;
    let p2 = bytes[1] as char;
    if matches!(p1, 'D' | 'F' | 'I' | 'Q' | 'U' | 'V' | 'O') {
        return false;
    }
    if matches!(p2, 'D' | 'F' | 'I' | 'O' | 'Q' | 'U' | 'V') {
        return false;
    }
    let prefix = &s[..2];
    if matches!(
        prefix,
        "BG" | "GB" | "KN" | "NK" | "NT" | "TN" | "ZZ"
    ) {
        return false;
    }
    let suffix = bytes[8] as char;
    matches!(suffix, 'A' | 'B' | 'C' | 'D')
}

/// Luhn check over an ASCII digit string. Public so callers writing
/// new PAN-like patterns can reuse it.
pub fn luhn_check(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut alt = false;
    for c in digits.chars().rev() {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        let v = if alt { d * 2 } else { d };
        sum += if v > 9 { v - 9 } else { v };
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

fn validate_pan_luhn(s: &str) -> bool {
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
        for s in ["123-45-6789", "555-12-3456", "888-55-4321"] {
            assert!(validate_ssn(s), "expected ok: {s}");
        }
    }

    #[test]
    fn ssn_validator_rejects_reserved_blocks() {
        for s in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "999-12-3456",
            "123-00-3456",
            "123-45-0000",
            "abc-de-fghi",
        ] {
            assert!(!validate_ssn(s), "expected reject: {s}");
        }
    }

    #[test]
    fn uk_ni_validator_accepts_valid_numbers() {
        for s in ["AB123456C", "JR987654A", "MA111111D"] {
            assert!(validate_uk_ni(s), "expected ok: {s}");
        }
    }

    #[test]
    fn uk_ni_validator_rejects_reserved_prefixes() {
        for s in ["BG123456A", "GB123456A", "NK123456A", "ZZ123456A"] {
            assert!(!validate_uk_ni(s), "expected reject: {s}");
        }
    }

    #[test]
    fn pan_validator_accepts_a_real_luhn_number() {
        // Stripe / Visa public test PAN.
        assert!(validate_pan_luhn("4242424242424242"));
        // 13-digit Visa test PAN.
        assert!(validate_pan_luhn("4222222222222"));
    }

    #[test]
    fn pan_validator_rejects_invalid_luhn_or_wrong_length() {
        assert!(!validate_pan_luhn("1234567890123"));
        assert!(!validate_pan_luhn("4242424242424243"));
        assert!(!validate_pan_luhn("1"));
        assert!(!validate_pan_luhn("12345678901234567890")); // 20 digits
    }

    #[test]
    fn luhn_check_handles_known_values() {
        assert!(luhn_check("79927398713"));
        assert!(!luhn_check("79927398710"));
        assert!(!luhn_check("not digits"));
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
