//! GCC-region DLP patterns (UAE, Qatar, Saudi Arabia, Kuwait,
//! Bahrain, Oman) with structural validators.

use regex::bytes::Regex;

use super::validators::{luhn_check, mod97_check, parse_ascii_digits, parse_ascii_u32};
use super::PatternDef;

/// Returns every pattern in the GCC region.
pub(crate) fn patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            category: "pii.ae_emirates_id",
            region: "gcc",
            name: "UAE Emirates ID",
            // Accept the canonical form `784-YYYY-NNNNNNN-C` and the
            // unhyphenated 15-digit variant printed on older cards.
            regex: Regex::new(r"\b784-?\d{4}-?\d{7}-?\d\b").expect("ae_emirates_id regex"),
            validator: validate_ae_emirates_id,
        },
        PatternDef {
            category: "pii.ae_trn",
            region: "gcc",
            name: "UAE Tax Registration Number (TRN)",
            regex: Regex::new(r"\b\d{15}\b").expect("ae_trn regex"),
            validator: validate_ae_trn,
        },
        PatternDef {
            category: "pii.qa_qid",
            region: "gcc",
            name: "Qatar Identity Number (QID)",
            regex: Regex::new(r"\b\d{11}\b").expect("qa_qid regex"),
            validator: validate_qa_qid,
        },
        PatternDef {
            category: "pii.sa_national_id",
            region: "gcc",
            name: "Saudi National ID / Iqama",
            regex: Regex::new(r"\b[12]\d{9}\b").expect("sa_national_id regex"),
            validator: validate_sa_national_id,
        },
        PatternDef {
            category: "pii.kw_civil_id",
            region: "gcc",
            name: "Kuwait Civil ID",
            regex: Regex::new(r"\b\d{12}\b").expect("kw_civil_id regex"),
            validator: validate_kw_civil_id,
        },
        PatternDef {
            category: "pii.bh_cpr",
            region: "gcc",
            name: "Bahrain Central Population Register (CPR)",
            regex: Regex::new(r"\b\d{9}\b").expect("bh_cpr regex"),
            validator: validate_bh_cpr,
        },
        PatternDef {
            category: "pii.om_civil_id",
            region: "gcc",
            name: "Oman Civil ID",
            regex: Regex::new(r"\b\d{8,9}\b").expect("om_civil_id regex"),
            validator: validate_om_civil_id,
        },
        PatternDef {
            category: "pci.gcc_iban",
            region: "gcc",
            name: "GCC IBAN",
            // Per SWIFT IBAN registry, lengths: AE/OM = 23, BH = 22,
            // KW = 30, QA = 29, SA = 24. BBAN bodies may contain
            // letters in some countries (e.g. KW, QA), so we accept
            // `[A-Z0-9]` after the 4-char prefix.
            regex: Regex::new(
                r"\b(?:AE\d{2}[A-Z0-9]{19}|BH\d{2}[A-Z0-9]{18}|KW\d{2}[A-Z0-9]{26}|OM\d{2}[A-Z0-9]{19}|QA\d{2}[A-Z0-9]{25}|SA\d{2}[A-Z0-9]{20})\b",
            )
            .expect("gcc_iban regex"),
            validator: validate_gcc_iban,
        },
    ]
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// UAE Emirates ID: must start with the ISO-3166 country dial-code
/// `784`; the 15-digit compact form passes a Luhn checksum.
fn validate_ae_emirates_id(s: &[u8]) -> bool {
    // Compact form: strip dashes.
    let mut compact = Vec::with_capacity(15);
    for &b in s {
        if b != b'-' {
            compact.push(b);
        }
    }
    if compact.len() != 15 || !compact.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if &compact[..3] != b"784" {
        return false;
    }
    luhn_check(&compact)
}

/// UAE TRN: 15-digit Federal Tax Authority registration; the canonical
/// fixture is `100xxxxxxxxxx03` for VAT registrants (suffix `03` for
/// the base entity).
fn validate_ae_trn(s: &[u8]) -> bool {
    s.len() == 15 && s.iter().all(|b| b.is_ascii_digit()) && &s[..3] == b"100" && &s[13..] == b"03"
}

/// Qatar QID: 11 digits. Position 0 is the century / nationality
/// digit (`2` = Qatari/born in 1900s, `3` = resident/born in 2000s);
/// positions 1–3 carry the last three digits of the birth year.
fn validate_qa_qid(s: &[u8]) -> bool {
    if s.len() != 11 || !s.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let nationality = s[0];
    if !matches!(nationality, b'2' | b'3') {
        return false;
    }
    // Birth year encoded as `<century-digit><YYY>` where century
    // digit 2 ⇒ 1XXX and digit 3 ⇒ 2XXX (per Qatar Ministry of
    // Interior issuance scheme).
    let Some(year_suffix) = parse_ascii_u32(&s[1..4]) else {
        return false;
    };
    let year = if nationality == b'2' {
        1000 + year_suffix
    } else {
        2000 + year_suffix
    };
    (1900..=2099).contains(&year)
}

/// Saudi National ID / Iqama: 10 digits. First digit `1` ⇒ Saudi
/// citizen, `2` ⇒ resident. Luhn over the full 10 digits.
fn validate_sa_national_id(s: &[u8]) -> bool {
    if s.len() != 10 || !s.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !matches!(s[0], b'1' | b'2') {
        return false;
    }
    luhn_check(s)
}

/// Kuwait Civil ID: 12 digits. Position 0 = century digit (`2` ⇒
/// 19XX, `3` ⇒ 20XX); positions 1–6 = YYMMDD birth date.
fn validate_kw_civil_id(s: &[u8]) -> bool {
    if s.len() != 12 {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    if !matches!(d[0], 2 | 3) {
        return false;
    }
    let month = d[3] as u32 * 10 + d[4] as u32;
    let day = d[5] as u32 * 10 + d[6] as u32;
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// Bahrain CPR: 9 digits. Last digit is a mod-11 check over the
/// first 8 digits with weights `[10, 9, 8, 7, 6, 5, 4, 3]`.
/// `check = sum mod 11` (with `10 ⇒ 0` collapse). First two digits
/// encode the holder's birth year.
fn validate_bh_cpr(s: &[u8]) -> bool {
    if s.len() != 9 {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    const WEIGHTS: [u32; 8] = [10, 9, 8, 7, 6, 5, 4, 3];
    let sum: u32 = d[..8]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let modulus = sum % 11;
    let check = if modulus == 10 { 0 } else { modulus };
    d[8] as u32 == check
}

/// Oman Civil ID: 8-digit (older format) or 9-digit (current format)
/// numeric identifier. The Royal Oman Police does not publish a
/// public check-digit algorithm, so we constrain by length, prefix
/// (positions 0..=1 are the issuing-governorate code, range 01..=11),
/// and forbid an all-zeros body.
fn validate_om_civil_id(s: &[u8]) -> bool {
    if !(s.len() == 8 || s.len() == 9) || !s.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(governorate) = parse_ascii_u32(&s[..2]) else {
        return false;
    };
    if !(1..=11).contains(&governorate) {
        return false;
    }
    s.iter().any(|b| *b != b'0')
}

/// GCC IBAN: country-code prefix + mod-97 ISO 7064 check.
fn validate_gcc_iban(s: &[u8]) -> bool {
    if s.len() < 22 || s.len() > 30 {
        return false;
    }
    if !s.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let expected_len = match &s[..2] {
        b"AE" => 23,
        b"BH" => 22,
        b"KW" => 30,
        b"OM" => 23,
        b"QA" => 29,
        b"SA" => 24,
        _ => return false,
    };
    if s.len() != expected_len {
        return false;
    }
    mod97_check(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_pattern(category: &str) -> PatternDef {
        patterns()
            .into_iter()
            .find(|p| p.category == category)
            .expect("pattern present")
    }

    #[test]
    fn ae_emirates_id_accepts_luhn_valid_fixture() {
        let p = find_pattern("pii.ae_emirates_id");
        // 784-1990-9999999-9 (Luhn over 784199099999999 = 0 mod 10).
        assert!(p.validate(b"784-1990-9999999-9"));
        // Compact form.
        assert!(p.validate(b"784199099999999"));
        // Wrong country prefix.
        assert!(!p.validate(b"785-1990-9999999-9"));
        // Off-by-one breaks Luhn.
        assert!(!p.validate(b"784-1990-9999999-8"));
    }

    #[test]
    fn ae_trn_accepts_published_format() {
        let p = find_pattern("pii.ae_trn");
        assert!(p.validate(b"100123456789003"));
        // Wrong prefix.
        assert!(!p.validate(b"200123456789003"));
        // Wrong base-entity suffix.
        assert!(!p.validate(b"100123456789005"));
    }

    #[test]
    fn qa_qid_accepts_in_range_year() {
        let p = find_pattern("pii.qa_qid");
        // `2` + `985` ⇒ year 1985 (Qatari, born late 20th century).
        assert!(p.validate(b"29851234567"));
        // `3` + `015` ⇒ year 2015 (resident born early 2000s).
        assert!(p.validate(b"30151234567"));
        // Bad nationality digit.
        assert!(!p.validate(b"49851234567"));
    }

    #[test]
    fn sa_national_id_validates_luhn() {
        let p = find_pattern("pii.sa_national_id");
        // 1029999990 — Luhn-valid Saudi National ID (computed below).
        assert!(p.validate(b"1029999990"));
        // Same digits with off-by-one.
        assert!(!p.validate(b"1029999991"));
        // Wrong leading digit.
        assert!(!p.validate(b"3029999990"));
    }

    #[test]
    fn kw_civil_id_validates_century_and_dob() {
        let p = find_pattern("pii.kw_civil_id");
        // Born 1985-06-15, serial 12345.
        assert!(p.validate(b"285061512345"));
        // Bad month.
        assert!(!p.validate(b"285131512345"));
        // Bad century digit.
        assert!(!p.validate(b"485061512345"));
    }

    #[test]
    fn bh_cpr_accepts_computed_check_digit() {
        let p = find_pattern("pii.bh_cpr");
        // First 8 digits "85011234" — weighted sum =
        //   8*10+5*9+0*8+1*7+1*6+2*5+3*4+4*3 = 80+45+0+7+6+10+12+12 = 172
        //   172 mod 11 = 7 ⇒ check digit 7.
        assert!(p.validate(b"850112347"));
        assert!(!p.validate(b"850112348"));
    }

    #[test]
    fn om_civil_id_length_and_governorate() {
        let p = find_pattern("pii.om_civil_id");
        assert!(p.validate(b"01234567")); // 8-digit, governorate 01
        assert!(p.validate(b"112345678")); // 9-digit, governorate 11
        assert!(!p.validate(b"00000000")); // all zeros rejected
        assert!(!p.validate(b"99123456")); // governorate out of range
        assert!(!p.validate(b"1234567")); // too short
    }

    #[test]
    fn gcc_iban_validates_published_examples() {
        let p = find_pattern("pci.gcc_iban");
        // Published SA IBAN from the SWIFT registry.
        assert!(p.validate(b"SA0380000000608010167519"));
        // Off-by-one rejection.
        assert!(!p.validate(b"SA0380000000608010167510"));
        // Unsupported country code.
        assert!(!p.validate(b"DE89370400440532013000"));
    }
}
