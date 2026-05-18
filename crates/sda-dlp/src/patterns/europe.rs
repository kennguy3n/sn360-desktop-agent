//! Europe-region DLP patterns with structural validators.

use regex::bytes::Regex;

use super::validators::{
    de_steuer_id_structure, ean13_check, iso7064_mod11_10, luhn_check, mod97_check,
    parse_ascii_digits, parse_ascii_u32,
};
use super::PatternDef;

pub(crate) const CATEGORIES: &[&str] = &[
    "pii.uk_ni",
    "pii.ch_ahv",
    "pii.ch_uid",
    "pci.ch_iban",
    "pii.de_steuer_id",
    "pii.fr_nir",
    "pii.nl_bsn",
    "pii.es_dni",
    "pii.it_cf",
    "pii.se_personnummer",
    "pii.pl_pesel",
    "pii.eu_vat",
    "pci.eu_iban",
];

/// Returns every pattern in the Europe region.
pub(crate) fn patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            category: "pii.uk_ni",
            region: "europe",
            name: "UK National Insurance Number",
            regex: Regex::new(r"\b[A-Z]{2}\d{6}[A-Z]\b").expect("uk_ni regex"),
            validator: validate_uk_ni,
        },
        PatternDef {
            category: "pii.ch_ahv",
            region: "europe",
            name: "Switzerland AHV / AVS (new format)",
            regex: Regex::new(r"\b756\.\d{4}\.\d{4}\.\d{2}\b").expect("ch_ahv regex"),
            validator: validate_ch_ahv,
        },
        PatternDef {
            category: "pii.ch_uid",
            region: "europe",
            name: "Switzerland Enterprise UID",
            regex: Regex::new(r"\bCHE-?\d{3}\.\d{3}\.\d{3}\b").expect("ch_uid regex"),
            validator: validate_ch_uid,
        },
        PatternDef {
            category: "pci.ch_iban",
            region: "europe",
            name: "Switzerland IBAN",
            regex: Regex::new(r"\bCH\d{2}[A-Z0-9]{17}\b").expect("ch_iban regex"),
            validator: validate_ch_iban,
        },
        PatternDef {
            category: "pii.de_steuer_id",
            region: "europe",
            name: "Germany Steueridentifikationsnummer",
            regex: Regex::new(r"\b\d{11}\b").expect("de_steuer regex"),
            validator: validate_de_steuer_id,
        },
        PatternDef {
            category: "pii.fr_nir",
            region: "europe",
            name: "France INSEE / NIR",
            // Department slot is two digits OR Corsica's `2A`/`2B`.
            // Validator substitutes 2A→19 and 2B→18 before mod-97.
            regex: Regex::new(
                r"\b[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{3}\d{3}\d{2}\b",
            )
            .expect("fr_nir regex"),
            validator: validate_fr_nir,
        },
        PatternDef {
            category: "pii.nl_bsn",
            region: "europe",
            name: "Netherlands Burgerservicenummer (BSN)",
            regex: Regex::new(r"\b\d{9}\b").expect("nl_bsn regex"),
            validator: validate_nl_bsn,
        },
        PatternDef {
            category: "pii.es_dni",
            region: "europe",
            name: "Spain DNI / NIE",
            regex: Regex::new(r"\b(?:\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b").expect("es_dni regex"),
            validator: validate_es_dni,
        },
        PatternDef {
            category: "pii.it_cf",
            region: "europe",
            name: "Italy Codice Fiscale",
            regex: Regex::new(
                r"\b[A-Z]{6}\d{2}[A-EHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b",
            )
            .expect("it_cf regex"),
            validator: validate_it_cf,
        },
        PatternDef {
            category: "pii.se_personnummer",
            region: "europe",
            name: "Sweden Personnummer",
            regex: Regex::new(r"\b\d{6}[-+]?\d{4}\b").expect("se_personnummer regex"),
            validator: validate_se_personnummer,
        },
        PatternDef {
            category: "pii.pl_pesel",
            region: "europe",
            name: "Poland PESEL",
            regex: Regex::new(r"\b\d{11}\b").expect("pl_pesel regex"),
            validator: validate_pl_pesel,
        },
        PatternDef {
            category: "pii.eu_vat",
            region: "europe",
            name: "EU VAT Number",
            // Each alternation closes with `\b` so a truncated prefix
            // (e.g. `DE12345678901` slicing 9 digits out of an 11-digit
            // run) cannot match — the surrounding token must end on a
            // non-word boundary too.
            //
            // Switzerland's CHE-prefixed VAT number is intentionally
            // OMITTED from this pattern: the bare `CHE-XXX.XXX.XXX`
            // form is byte-for-byte identical to the Swiss enterprise
            // UID, which has its own dedicated `pii.ch_uid` pattern
            // (running the issuer's mod-11 check). Including CHE here
            // would produce two `LocalDetectionAlert` events for the
            // same number (UID + VAT). Per the Swiss FDF, the UID and
            // VAT number are the same identifier — operators care
            // about leaking the number, not which detector noticed
            // first.
            regex: Regex::new(
                r"\b(?:AT)U\d{8}\b|\b(?:BE)0\d{9}\b|\b(?:DE|EE|EL|GR|PT)\d{9}\b|\b(?:DK|FI|HU|LU|MT|SI)\d{8}\b|\b(?:CY|CZ|ES|HR)[A-Z0-9]{8,11}\b|\b(?:FR)[A-Z0-9]{2}\d{9}\b|\b(?:IT|LT|LV|PL|SK)\d{10,12}\b|\b(?:NL)\d{9}B\d{2}\b|\b(?:SE)\d{12}\b",
            )
            .expect("eu_vat regex"),
            validator: validate_eu_vat,
        },
        PatternDef {
            category: "pci.eu_iban",
            region: "europe",
            name: "EU IBAN",
            // Broad ISO 13616 prefix + 2 check + up to 30 BBAN chars.
            // Country / length combinations are enforced by the
            // validator's per-country length table.
            regex: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").expect("eu_iban regex"),
            validator: validate_eu_iban,
        },
    ]
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// UK National Insurance number — preserved verbatim from the original
/// baseline so its semantics don't drift when we move it to the
/// europe module.
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

/// Switzerland AHV/AVS: `756.XXXX.XXXX.YY` where the final two digits
/// close an EAN-13 check digit.
fn validate_ch_ahv(s: &[u8]) -> bool {
    if s.len() != 16 {
        return false;
    }
    let mut compact = [0u8; 13];
    let mut idx = 0;
    for &b in s {
        if b == b'.' {
            continue;
        }
        if idx >= 13 || !b.is_ascii_digit() {
            return false;
        }
        compact[idx] = b;
        idx += 1;
    }
    if idx != 13 || &compact[..3] != b"756" {
        return false;
    }
    ean13_check(&compact)
}

/// Switzerland enterprise UID: `CHE-XXX.XXX.XXX` where the 9th digit
/// is a weighted mod-11 check over the first 8 digits.
fn validate_ch_uid(s: &[u8]) -> bool {
    // Compact the 9 digits after stripping `CHE`, `-`, `.`.
    let mut compact = [0u8; 9];
    let mut idx = 0;
    let mut iter = s.iter();
    // Skip CHE prefix.
    for _ in 0..3 {
        iter.next();
    }
    for &b in iter {
        if b == b'-' || b == b'.' {
            continue;
        }
        if idx >= 9 || !b.is_ascii_digit() {
            return false;
        }
        compact[idx] = b;
        idx += 1;
    }
    if idx != 9 {
        return false;
    }
    let Some(d) = parse_ascii_digits(&compact) else {
        return false;
    };
    const WEIGHTS: [u32; 8] = [5, 4, 3, 2, 7, 6, 5, 4];
    let sum: u32 = d[..8]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let r = sum % 11;
    if r == 0 {
        return d[8] == 0;
    }
    let check = 11 - r;
    if check == 10 {
        // 10 is unrepresentable in a single decimal — the issuer
        // re-rolls the serial, so this number cannot be valid.
        return false;
    }
    d[8] as u32 == check
}

/// Switzerland IBAN: 21 characters (CH + 2 + 17 alphanumeric BBAN),
/// closed by ISO 7064 mod-97.
fn validate_ch_iban(s: &[u8]) -> bool {
    s.len() == 21 && mod97_check(s)
}

/// Germany Steueridentifikationsnummer: ISO 7064 mod-11,10 check
/// digit PLUS the §139b structural rule on the leading 10 digits.
fn validate_de_steuer_id(s: &[u8]) -> bool {
    if s.len() != 11 || !s.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Leading zero is not issued by BZSt.
    if s[0] == b'0' {
        return false;
    }
    iso7064_mod11_10(s) && de_steuer_id_structure(s)
}

/// France INSEE / NIR: 15-character ID covering sex + year + month +
/// department + commune + serial + 2-digit check. The check digit is
/// `97 - (body mod 97)` where `body` is the 13-digit prefix.
///
/// Positions 5–6 are the department code. Most departments encode as
/// two digits, but Corsica uses `2A` / `2B`. Per INSEE, those are
/// substituted with `19` / `18` respectively before the mod-97
/// computation; the rest of the ID stays untouched.
fn validate_fr_nir(s: &[u8]) -> bool {
    if s.len() != 15 {
        return false;
    }
    // Body positions 0–4 (sex + year + month) and 7–12 (commune +
    // serial) plus the 2-digit check at 13–14 are always decimal.
    if !s[..5].iter().all(|b| b.is_ascii_digit()) || !s[7..].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Department slot accepts either two digits or Corsica's 2A/2B.
    let (dept_d5, dept_d6) = match (s[5], s[6]) {
        (b'2', b'A') => (b'1', b'9'),
        (b'2', b'B') => (b'1', b'8'),
        (a, b) if a.is_ascii_digit() && b.is_ascii_digit() => (a, b),
        _ => return false,
    };
    // Materialise the 13-digit body with the substitution applied.
    let mut body = [0u8; 13];
    body[..5].copy_from_slice(&s[..5]);
    body[5] = dept_d5;
    body[6] = dept_d6;
    body[7..].copy_from_slice(&s[7..13]);
    let Some(d) = parse_ascii_digits(&body) else {
        return false;
    };
    // Month field: 01–12 for known months, 20–99 for unknown / pseudonymised.
    let month = d[3] as u32 * 10 + d[4] as u32;
    if !(1..=12).contains(&month) && !(20..=99).contains(&month) {
        return false;
    }
    let mut number: u64 = 0;
    for &digit in &d {
        number = number * 10 + digit as u64;
    }
    let expected = (97 - (number % 97)) as u32;
    let check = (s[13] - b'0') as u32 * 10 + (s[14] - b'0') as u32;
    check == expected
}

/// Netherlands Burgerservicenummer: 9-digit eleven-test.
fn validate_nl_bsn(s: &[u8]) -> bool {
    if s.len() != 9 {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    let weights = [9i32, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = d
        .iter()
        .zip(weights.iter())
        .map(|(d, w)| (*d as i32) * w)
        .sum();
    sum % 11 == 0 && sum != 0
}

/// Spain DNI/NIE: 8-digit number with single check letter from
/// `TRWAGMYFPDXBNJZSQVHLCKE` indexed by `number mod 23`. NIE prefixes
/// X/Y/Z map to leading digits 0/1/2.
fn validate_es_dni(s: &[u8]) -> bool {
    const LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let (number_bytes, letter) = if s.len() == 9 {
        let first = s[0];
        let letter = s[8];
        let mut buf = [0u8; 8];
        match first {
            b'X' => buf[0] = b'0',
            b'Y' => buf[0] = b'1',
            b'Z' => buf[0] = b'2',
            b'0'..=b'9' => buf[0] = first,
            _ => return false,
        }
        buf[1..].copy_from_slice(&s[1..8]);
        (buf, letter)
    } else {
        return false;
    };
    let Some(number) = parse_ascii_u32(&number_bytes) else {
        return false;
    };
    LETTERS[(number % 23) as usize] == letter
}

/// Italy Codice Fiscale: alphanumeric 16-char structure with a
/// position-weighted check character (odd positions use a
/// substitution table, even positions use straight A=0..Z=25 / digit
/// face value).
fn validate_it_cf(s: &[u8]) -> bool {
    if s.len() != 16 {
        return false;
    }
    fn odd_value(b: u8) -> Option<u32> {
        match b {
            b'0' | b'A' => Some(1),
            b'1' | b'B' => Some(0),
            b'2' | b'C' => Some(5),
            b'3' | b'D' => Some(7),
            b'4' | b'E' => Some(9),
            b'5' | b'F' => Some(13),
            b'6' | b'G' => Some(15),
            b'7' | b'H' => Some(17),
            b'8' | b'I' => Some(19),
            b'9' | b'J' => Some(21),
            b'K' => Some(2),
            b'L' => Some(4),
            b'M' => Some(18),
            b'N' => Some(20),
            b'O' => Some(11),
            b'P' => Some(3),
            b'Q' => Some(6),
            b'R' => Some(8),
            b'S' => Some(12),
            b'T' => Some(14),
            b'U' => Some(16),
            b'V' => Some(10),
            b'W' => Some(22),
            b'X' => Some(25),
            b'Y' => Some(24),
            b'Z' => Some(23),
            _ => None,
        }
    }
    fn even_value(b: u8) -> Option<u32> {
        match b {
            b'0'..=b'9' => Some((b - b'0') as u32),
            b'A'..=b'Z' => Some((b - b'A') as u32),
            _ => None,
        }
    }
    let mut sum: u32 = 0;
    for (i, &b) in s[..15].iter().enumerate() {
        let v = if i % 2 == 0 {
            // 1-indexed odd ⇒ 0-indexed even.
            odd_value(b)
        } else {
            even_value(b)
        };
        match v {
            Some(x) => sum += x,
            None => return false,
        }
    }
    let expected = b'A' + (sum % 26) as u8;
    s[15] == expected
}

/// Sweden Personnummer: 10-digit core with optional `-` / `+` between
/// year and serial. The 10 digits are Luhn-protected.
///
/// Also accepts samordningsnummer (coordination numbers): the day
/// field is offset by +60 so the legal range becomes 61..=91. They
/// share the personnummer structure and Luhn-check digit, and the
/// Swedish Tax Agency treats both as the same number space.
fn validate_se_personnummer(s: &[u8]) -> bool {
    let mut compact = Vec::with_capacity(10);
    for &b in s {
        if b == b'-' || b == b'+' {
            continue;
        }
        compact.push(b);
    }
    if compact.len() != 10 || !compact.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Birth month/day sanity (positions 2..6 in the compact form
    // encode MMDD; samordningsnummer add 60 to DD).
    let month = (compact[2] - b'0') as u32 * 10 + (compact[3] - b'0') as u32;
    let day = (compact[4] - b'0') as u32 * 10 + (compact[5] - b'0') as u32;
    let day_ok = (1..=31).contains(&day) || (61..=91).contains(&day);
    if !(1..=12).contains(&month) || !day_ok {
        return false;
    }
    luhn_check(&compact)
}

/// Poland PESEL: 11 digits, weighted mod-10 check (weights
/// `[1,3,7,9,1,3,7,9,1,3]` over the first 10 digits) plus DOB sanity.
fn validate_pl_pesel(s: &[u8]) -> bool {
    if s.len() != 11 || !s.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    // Birth-month encoding includes century offset:
    //   1900-1999 → 01..12
    //   2000-2099 → 21..32
    //   1800-1899 → 81..92
    //   2100-2199 → 41..52
    //   2200-2299 → 61..72
    let mm_field = d[2] as u32 * 10 + d[3] as u32;
    let dd = d[4] as u32 * 10 + d[5] as u32;
    let month = mm_field % 20;
    if !(1..=12).contains(&month) || !(1..=31).contains(&dd) {
        return false;
    }
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = d[..10]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let check = (10 - sum % 10) % 10;
    d[10] as u32 == check
}

/// EU VAT: structural prefix validation. Full per-country check
/// digit algorithms are out of scope here; we use the regex to
/// constrain length and prefix and ensure the body is the right
/// alphabet, which is enough to keep the false-positive rate in
/// check.
///
/// Switzerland's CHE-form VAT is handled by the dedicated
/// `pii.ch_uid` pattern (same number, with a real mod-11 check) —
/// see the pattern definition for the rationale.
fn validate_eu_vat(s: &[u8]) -> bool {
    if s.len() < 4 {
        return false;
    }
    if !s[0].is_ascii_uppercase() || !s[1].is_ascii_uppercase() {
        return false;
    }
    let prefix = &s[..2];
    let body = &s[2..];
    let digit_count = body.iter().filter(|b| b.is_ascii_digit()).count();
    // Per-country body shape guards.
    match prefix {
        b"AT" => body.starts_with(b"U") && body.len() == 9 && digit_count == 8,
        b"BE" => body.len() == 10 && body[0] == b'0',
        b"DE" | b"EE" | b"EL" | b"GR" | b"PT" => body.len() == 9 && digit_count == 9,
        b"DK" | b"FI" | b"HU" | b"LU" | b"MT" | b"SI" => body.len() == 8 && digit_count == 8,
        b"FR" => body.len() == 11 && body[..2].iter().all(|b| b.is_ascii_alphanumeric()),
        b"NL" => body.len() == 12 && body[9] == b'B' && digit_count == 11,
        b"SE" => body.len() == 12 && digit_count == 12,
        b"IT" | b"LT" | b"LV" | b"PL" | b"SK" => {
            (body.len() == 10 || body.len() == 11 || body.len() == 12) && digit_count == body.len()
        }
        b"CY" | b"CZ" | b"ES" | b"HR" => {
            body.len() >= 8 && body.len() <= 11 && body.iter().all(|b| b.is_ascii_alphanumeric())
        }
        _ => false,
    }
}

/// EU IBAN (broad): per-country length table from the SWIFT IBAN
/// registry + ISO 7064 mod-97.
fn validate_eu_iban(s: &[u8]) -> bool {
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    let prefix = &s[..2];
    let expected = match prefix {
        b"AL" => 28,
        b"AD" => 24,
        b"AT" => 20,
        b"BA" => 20,
        b"BE" => 16,
        b"BG" => 22,
        // Switzerland is handled by the dedicated `pci.ch_iban`
        // pattern. Rejecting it here keeps a single Swiss IBAN from
        // producing two `LocalDetectionAlert` events (one per
        // pattern) — operators care about the country, not which
        // detector noticed first.
        b"CH" => return false,
        b"CY" => 28,
        b"CZ" => 24,
        b"DE" => 22,
        b"DK" => 18,
        b"EE" => 20,
        b"ES" => 24,
        b"FI" => 18,
        b"FO" => 18,
        b"FR" => 27,
        b"GB" => 22,
        b"GI" => 23,
        b"GL" => 18,
        b"GR" => 27,
        b"HR" => 21,
        b"HU" => 28,
        b"IE" => 22,
        b"IS" => 26,
        b"IT" => 27,
        b"LI" => 21,
        b"LT" => 20,
        b"LU" => 20,
        b"LV" => 21,
        b"MC" => 27,
        b"ME" => 22,
        b"MK" => 19,
        b"MT" => 31,
        b"NL" => 18,
        b"NO" => 15,
        b"PL" => 28,
        b"PT" => 25,
        b"RO" => 24,
        b"RS" => 22,
        b"SE" => 24,
        b"SI" => 19,
        b"SK" => 24,
        b"SM" => 27,
        _ => return false,
    };
    if s.len() != expected {
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
    fn uk_ni_still_validates() {
        let p = find_pattern("pii.uk_ni");
        assert!(p.validate(b"AB123456C"));
        assert!(!p.validate(b"BG123456C")); // reserved prefix
        assert!(!p.validate(b"AB123456E")); // bad suffix
    }

    #[test]
    fn ch_ahv_accepts_known_format() {
        let p = find_pattern("pii.ch_ahv");
        // EAN-13 valid (7569217076985).
        assert!(p.validate(b"756.9217.0769.85"));
        // Off-by-one breaks EAN-13.
        assert!(!p.validate(b"756.9217.0769.84"));
        // Wrong country prefix.
        assert!(!p.validate(b"757.9217.0769.85"));
    }

    #[test]
    fn ch_uid_accepts_check_digit() {
        let p = find_pattern("pii.ch_uid");
        // sum = 1*5+2*4+3*3+4*2+5*7+6*6+7*5+8*4 = 168; mod 11 = 3 ⇒ check 8.
        assert!(p.validate(b"CHE-123.456.788"));
        // Off-by-one rejects.
        assert!(!p.validate(b"CHE-123.456.789"));
    }

    #[test]
    fn ch_iban_validates_published_iban() {
        let p = find_pattern("pci.ch_iban");
        assert!(p.validate(b"CH9300762011623852957"));
        assert!(!p.validate(b"CH9300762011623852958"));
    }

    #[test]
    fn de_steuer_id_validates_published_id() {
        let p = find_pattern("pii.de_steuer_id");
        // Public BZSt fixture from §139b AO commentary.
        assert!(p.validate(b"86095742719"));
        // Off-by-one breaks ISO 7064.
        assert!(!p.validate(b"86095742718"));
        // Repeats every-digit-unique fails the structural rule.
        assert!(!p.validate(b"01234567890"));
    }

    #[test]
    fn fr_nir_validates_published_id() {
        let p = find_pattern("pii.fr_nir");
        // INSEE published fixture.
        assert!(p.validate(b"184127645108946"));
        assert!(!p.validate(b"184127645108945"));
        // Invalid month.
        assert!(!p.validate(b"184137645108946"));
    }

    #[test]
    fn fr_nir_accepts_corsica_department_codes() {
        let p = find_pattern("pii.fr_nir");
        // Corsica-du-Sud (2A): body 17506·2A·005·001 → after 2A→19
        // substitution the 13-digit body is 1750619005001 and the
        // check digit is 97 - (n mod 97) = 72.
        assert!(p.validate(b"175062A00500172"));
        // Haute-Corse (2B): body 17506·2B·005·001 → after 2B→18
        // substitution the body is 1750618005001 and the check is 02.
        assert!(p.validate(b"175062B00500102"));
        // Off-by-one breaks the mod-97 check.
        assert!(!p.validate(b"175062A00500173"));
        assert!(!p.validate(b"175062B00500103"));
        // Letters outside the Corsica positions are rejected.
        assert!(!p.validate(b"17506AA00500172"));
        assert!(!p.validate(b"175062C00500172"));
    }

    #[test]
    fn nl_bsn_eleven_test() {
        let p = find_pattern("pii.nl_bsn");
        assert!(p.validate(b"123456782")); // weighted sum 154, ÷11
        assert!(p.validate(b"111222333"));
        assert!(!p.validate(b"123456789"));
        assert!(!p.validate(b"000000000"));
    }

    #[test]
    fn es_dni_letter_lookup() {
        let p = find_pattern("pii.es_dni");
        assert!(p.validate(b"12345678Z")); // 12345678 mod 23 = 14 ⇒ Z
        assert!(p.validate(b"X1234567L")); // 1234567 mod 23 = 19 ⇒ L
        assert!(!p.validate(b"12345678A")); // wrong letter
    }

    #[test]
    fn it_cf_validates_check_character() {
        let p = find_pattern("pii.it_cf");
        // Mario Rossi 1925-04-09 (Wikipedia example).
        assert!(p.validate(b"MRTMTT25D09F205Z"));
        // Off-by-one breaks the check character.
        assert!(!p.validate(b"MRTMTT25D09F205A"));
    }

    #[test]
    fn se_personnummer_luhn_check() {
        let p = find_pattern("pii.se_personnummer");
        assert!(p.validate(b"640823-3234"));
        assert!(p.validate(b"6408233234"));
        assert!(!p.validate(b"640823-3235"));
        // Invalid month.
        assert!(!p.validate(b"641323-3234"));
    }

    #[test]
    fn se_personnummer_accepts_samordningsnummer() {
        // Samordningsnummer (coordination number): birth day is
        // shifted by +60, so a legal value is 61..=91. The Luhn-check
        // digit is computed over the raw 10 digits, including the
        // +60 offset — Skatteverket treats personnummer and
        // samordningsnummer as one number space.
        let p = find_pattern("pii.se_personnummer");
        // Day 20 + 60 = 80 (samordningsnummer for someone born on the
        // 20th of October 1985). 8510801239 is Luhn-valid.
        assert!(p.validate(b"851080-1239"));
        assert!(p.validate(b"8510801239"));
        // Off-by-one Luhn rejection.
        assert!(!p.validate(b"8510801238"));
        // Day outside both personnummer (1..=31) and samordningsnummer
        // (61..=91) ranges.
        assert!(!p.validate(b"851050-1234"));
        assert!(!p.validate(b"851092-1234"));
    }

    #[test]
    fn pl_pesel_weighted_check_and_dob() {
        let p = find_pattern("pii.pl_pesel");
        assert!(p.validate(b"02070803628"));
        assert!(!p.validate(b"02070803629"));
    }

    #[test]
    fn eu_vat_prefix_and_shape() {
        let p = find_pattern("pii.eu_vat");
        assert!(p.validate(b"DE123456789"));
        assert!(p.validate(b"ATU12345678"));
        assert!(p.validate(b"NL123456789B01"));
        // Switzerland's CHE-prefixed VAT is intentionally NOT
        // matched here — see the `pii.eu_vat` regex doc-comment and
        // the dedicated `pii.ch_uid` pattern.
        assert!(!p.regex.is_match(b"CHE-123.456.788"));
        assert!(!p.validate(b"XX123456789")); // unknown prefix
        assert!(!p.validate(b"ATY12345678")); // AT body must start with U
    }

    #[test]
    fn eu_iban_per_country_length_and_mod97() {
        let p = find_pattern("pci.eu_iban");
        assert!(p.validate(b"DE89370400440532013000"));
        assert!(p.validate(b"GB82WEST12345698765432"));
        assert!(p.validate(b"FR1420041010050500013M02606"));
        // Mod-97 corruption.
        assert!(!p.validate(b"DE89370400440532013001"));
        // Wrong length for the prefix.
        assert!(!p.validate(b"DE893704004405320130"));
    }
}
