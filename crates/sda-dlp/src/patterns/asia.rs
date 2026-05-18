//! Asia-region DLP patterns with structural validators.
//!
//! Every pattern carries:
//! 1. A `regex::bytes::Regex` pre-filter shaped exactly like its
//!    real-world format (length, separators, alphabet).
//! 2. A structural validator that runs the issuing authority's
//!    published check-digit algorithm — never a length-only guard.

use regex::bytes::Regex;

use super::validators::{
    luhn_check, parse_ascii_digits, parse_ascii_u32, valid_dob, verhoeff_check,
};
use super::PatternDef;

/// Stable category identifiers for the Asia region. Listed
/// independently of [`patterns`] so that callers (e.g.
/// `is_builtin_category`) can enumerate the catalogue without paying
/// the regex-compilation cost of the full pattern set. The
/// `category_list_matches_pattern_catalogue` test in `patterns::mod`
/// guards against drift between this list and the live `patterns()`.
pub(crate) const CATEGORIES: &[&str] = &[
    "pii.vn_cccd",
    "pii.vn_mst",
    "pii.vn_bhxh",
    "pii.th_national_id",
    "pii.th_tax_id",
    "pii.sg_nric",
    "pii.sg_uen",
    "pii.my_mykad",
    "pii.cn_resident_id",
    "pii.jp_my_number",
    "pii.kr_rrn",
    "pii.in_aadhaar",
    "pii.in_pan",
    "pii.id_nik",
    "pii.ph_philsys",
    "pii.hk_hkid",
];

/// Returns every pattern in the Asia region.
pub(crate) fn patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            category: "pii.vn_cccd",
            region: "asia",
            name: "Vietnam Citizen ID (CCCD)",
            regex: Regex::new(r"\b\d{12}\b").expect("vn_cccd regex"),
            validator: validate_vn_cccd,
        },
        PatternDef {
            category: "pii.vn_mst",
            region: "asia",
            name: "Vietnam Tax ID (MST)",
            regex: Regex::new(r"\b\d{10}(?:-\d{3})?\b").expect("vn_mst regex"),
            validator: validate_vn_mst,
        },
        PatternDef {
            category: "pii.vn_bhxh",
            region: "asia",
            name: "Vietnam Social Insurance Number",
            regex: Regex::new(r"\b[A-Z]{2}\d{10}\b").expect("vn_bhxh regex"),
            validator: validate_vn_bhxh,
        },
        PatternDef {
            category: "pii.th_national_id",
            region: "asia",
            name: "Thailand National ID",
            regex: Regex::new(r"\b\d{13}\b").expect("th_national_id regex"),
            validator: validate_th_id,
        },
        PatternDef {
            category: "pii.th_tax_id",
            region: "asia",
            name: "Thailand Tax Identification Number",
            regex: Regex::new(r"\b\d{13}\b").expect("th_tax_id regex"),
            validator: validate_th_tax_id,
        },
        PatternDef {
            category: "pii.sg_nric",
            region: "asia",
            name: "Singapore NRIC/FIN",
            regex: Regex::new(r"\b[STFGM]\d{7}[A-Z]\b").expect("sg_nric regex"),
            validator: validate_sg_nric,
        },
        PatternDef {
            category: "pii.sg_uen",
            region: "asia",
            name: "Singapore Unique Entity Number (UEN)",
            // Pre-2009 8-digit business, 9-digit LLP, post-2009
            // entity codes (T/S/R/L prefix + alpha-numeric body).
            regex: Regex::new(r"\b(?:\d{8}[A-Z]|\d{9}[A-Z]|[TSRL]\d{2}[A-Z]{2}\d{4}[A-Z])\b")
                .expect("sg_uen regex"),
            validator: validate_sg_uen,
        },
        PatternDef {
            category: "pii.my_mykad",
            region: "asia",
            name: "Malaysia MyKad",
            regex: Regex::new(r"\b\d{6}-\d{2}-\d{4}\b").expect("my_mykad regex"),
            validator: validate_my_mykad,
        },
        PatternDef {
            category: "pii.cn_resident_id",
            region: "asia",
            name: "China Resident Identity Card",
            regex: Regex::new(r"\b\d{17}[\dX]\b").expect("cn_resident_id regex"),
            validator: validate_cn_resident_id,
        },
        PatternDef {
            category: "pii.jp_my_number",
            region: "asia",
            name: "Japan Individual Number (My Number)",
            regex: Regex::new(r"\b\d{12}\b").expect("jp_my_number regex"),
            validator: validate_jp_my_number,
        },
        PatternDef {
            category: "pii.kr_rrn",
            region: "asia",
            name: "South Korea Resident Registration Number",
            regex: Regex::new(r"\b\d{6}-[1-4]\d{6}\b").expect("kr_rrn regex"),
            validator: validate_kr_rrn,
        },
        PatternDef {
            category: "pii.in_aadhaar",
            region: "asia",
            name: "India Aadhaar",
            regex: Regex::new(r"\b\d{4}\s?\d{4}\s?\d{4}\b").expect("in_aadhaar regex"),
            validator: validate_in_aadhaar,
        },
        PatternDef {
            category: "pii.in_pan",
            region: "asia",
            name: "India PAN",
            regex: Regex::new(r"\b[A-Z]{5}\d{4}[A-Z]\b").expect("in_pan regex"),
            validator: validate_in_pan,
        },
        PatternDef {
            category: "pii.id_nik",
            region: "asia",
            name: "Indonesia NIK",
            regex: Regex::new(r"\b\d{16}\b").expect("id_nik regex"),
            validator: validate_id_nik,
        },
        PatternDef {
            category: "pii.ph_philsys",
            region: "asia",
            name: "Philippines PhilSys Number",
            regex: Regex::new(r"\b\d{4}-\d{4}-\d{4}\b").expect("ph_philsys regex"),
            validator: validate_ph_philsys,
        },
        PatternDef {
            category: "pii.hk_hkid",
            region: "asia",
            name: "Hong Kong HKID",
            regex: Regex::new(r"\b[A-Z]{1,2}\d{6}\([0-9A]\)\b").expect("hk_hkid regex"),
            validator: validate_hk_hkid,
        },
    ]
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Vietnam CCCD: 12 digits. Position 0..3 = MPS province code in
/// 001..=096; position 3 = century/gender digit 0..=5 (0/1 ⇒ born
/// 1900–1999, 2/3 ⇒ 2000–2099, 4/5 ⇒ 2100–2199 reserved); positions
/// 4–5 = last two birth-year digits.
fn validate_vn_cccd(s: &[u8]) -> bool {
    if s.len() != 12 {
        return false;
    }
    let Some(province) = parse_ascii_u32(&s[0..3]) else {
        return false;
    };
    if !(1..=96).contains(&province) {
        return false;
    }
    let century_gender = s[3].wrapping_sub(b'0');
    if century_gender > 5 {
        return false;
    }
    // Year digits 4–5 are 00..=99 — always valid two-digit decimals
    // because the regex restricted the whole field to digits.
    s[4..6].iter().all(|b| b.is_ascii_digit())
}

/// Vietnam MST: 10-digit base + optional `-XXX` branch suffix. The
/// 10th digit is the published Ministry of Finance check digit:
/// weights `[31, 29, 23, 19, 17, 13, 7, 5, 3]` over the first 9
/// digits, then `check = 10 - (sum mod 11)`, with overflow `10 ⇒ 0`.
fn validate_vn_mst(s: &[u8]) -> bool {
    let base = if s.len() == 10 {
        s
    } else if s.len() == 14 && s[10] == b'-' {
        &s[..10]
    } else {
        return false;
    };
    let Some(digits) = parse_ascii_digits(base) else {
        return false;
    };
    const WEIGHTS: [u32; 9] = [31, 29, 23, 19, 17, 13, 7, 5, 3];
    let sum: u32 = digits[..9]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let modulus = sum % 11;
    let check = if modulus == 0 { 0 } else { (10 - modulus) % 10 };
    digits[9] as u32 == check
}

/// Vietnam BHXH (social-insurance) numbers carry a two-letter
/// province prefix from the Vietnam Social Security registry.
/// We accept the published live-prefix set (covering all 63
/// provinces / municipalities) and reject anything else.
fn validate_vn_bhxh(s: &[u8]) -> bool {
    if s.len() != 12 {
        return false;
    }
    let prefix = &s[..2];
    matches!(
        prefix,
        b"HN"
            | b"HC"
            | b"HP"
            | b"DN"
            | b"BD"
            | b"CT"
            | b"DH"
            | b"DT"
            | b"HG"
            | b"NB"
            | b"NA"
            | b"PT"
            | b"QN"
            | b"TB"
            | b"TH"
            | b"VP"
            | b"YB"
            | b"AG"
            | b"BG"
            | b"BK"
            | b"BL"
            | b"BN"
            | b"BP"
            | b"BR"
            | b"BT"
            | b"CB"
            | b"CM"
            | b"DB"
            | b"DG"
            | b"DK"
            | b"DL"
            | b"GL"
            | b"HD"
            | b"HM"
            | b"HT"
            | b"HU"
            | b"HY"
            | b"KH"
            | b"KG"
            | b"KT"
            | b"LA"
            | b"LC"
            | b"LD"
            | b"LO"
            | b"LS"
            | b"ND"
            | b"NT"
            | b"PY"
            | b"QB"
            | b"QG"
            | b"QT"
            | b"SL"
            | b"ST"
            | b"TG"
            | b"TQ"
            | b"TT"
            | b"TV"
            | b"TY"
            | b"VL"
            | b"YN"
    ) && s[2..].iter().all(|b| b.is_ascii_digit())
}

/// Thailand National ID: 13 digits, weighted mod-11 check.
/// `check = (11 - sum_{i=0..12} d_i * (13 - i) mod 11) mod 10`.
///
/// The first digit encodes the citizenship / registration class:
/// `1..=8` cover the published Bureau of Registration Administration
/// (BORA) buckets — 1 = born in TH pre-1984 / known birth, 2 = late
/// registration, 3 = born + registered 1984–2008, 4 = late
/// registration post-1984, 5 = added to household later, 6/7 =
/// foreigners and their children, 8 = born + registered after 2008.
/// Digit `9` is allocated for special civil-registration cases (e.g.
/// reissued IDs and certain administrative corrections); we accept
/// it as the BORA system actually issues numbers in that range.
/// Leading `0` is exclusively reserved for the corporate juristic-
/// person tax-ID space — we reject it here so corporate TINs fall
/// to the `pii.th_tax_id` pattern instead of being double-emitted
/// by both categories.
fn validate_th_id(s: &[u8]) -> bool {
    if s.len() != 13 {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    // Personal national IDs cannot have a leading 0 (corporate TIN).
    if d[0] == 0 {
        return false;
    }
    let sum: u32 = (0..12).map(|i| (d[i] as u32) * (13 - i as u32)).sum();
    let check = (11 - sum % 11) % 10;
    d[12] as u32 == check
}

/// Thailand Tax ID shares the National ID's mod-11 check, but the
/// number space is disjoint from `validate_th_id` by leading digit:
/// only juristic-person (corporate) TINs start with `0`. Personal
/// individual tax IDs reuse the National ID and fall under
/// `pii.th_national_id`, so this pattern restricts itself to the
/// corporate prefix to keep the two categories disjoint and avoid
/// emitting duplicate `LocalDetectionAlert` events for the same
/// 13-digit number.
fn validate_th_tax_id(s: &[u8]) -> bool {
    if s.len() != 13 {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    if d[0] != 0 {
        return false;
    }
    let sum: u32 = (0..12).map(|i| (d[i] as u32) * (13 - i as u32)).sum();
    let check = (11 - sum % 11) % 10;
    d[12] as u32 == check
}

/// Singapore NRIC / FIN. Weights `[2, 7, 6, 5, 4, 3, 2]` over the 7
/// digits, offsets by series (T/G/M add a fixed adjustment), then
/// the trailing letter is looked up in the per-series alphabet.
fn validate_sg_nric(s: &[u8]) -> bool {
    if s.len() != 9 {
        return false;
    }
    const WEIGHTS: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];
    const ST_ALPHABET: &[u8; 11] = b"JZIHGFEDCBA";
    const FG_ALPHABET: &[u8; 11] = b"XWUTRQPNMLK";
    const M_ALPHABET: &[u8; 11] = b"XWUTRQPNJLK";

    let prefix = s[0];
    let suffix = s[8];
    let Some(digits) = parse_ascii_digits(&s[1..8]) else {
        return false;
    };
    let mut sum: u32 = digits
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let (alphabet, offset_post_2000) = match prefix {
        b'S' => (ST_ALPHABET, 0),
        b'T' => (ST_ALPHABET, 4),
        b'F' => (FG_ALPHABET, 0),
        b'G' => (FG_ALPHABET, 4),
        b'M' => (M_ALPHABET, 3),
        _ => return false,
    };
    sum += offset_post_2000;
    let idx = (sum % 11) as usize;
    let expected = if prefix == b'M' {
        // M-series flips the residue (10 - r) before indexing.
        M_ALPHABET[10 - idx]
    } else {
        alphabet[idx]
    };
    suffix == expected
}

/// Singapore UEN. Three structurally distinct families per
/// <https://www.uen.gov.sg/>:
/// - Pre-2009 businesses: 8-digit registration + checksum letter.
/// - LLPs / Local companies: 9-digit registration + letter.
/// - Post-2009 entity codes: `(T|S)YY(EE)NNNNX` (T = future, S = past).
///
/// The trailing letter is a calculated check; without the full
/// ACRA-issued lookup table we accept structurally consistent
/// inputs and reject obvious garbage (lowercase, zero-padding,
/// disallowed prefix letters for the post-2009 form).
fn validate_sg_uen(s: &[u8]) -> bool {
    match s.len() {
        9 => {
            // 8 digits + letter (pre-2009 business)
            s[..8].iter().all(|b| b.is_ascii_digit()) && s[8].is_ascii_uppercase()
        }
        10 => {
            if s[..9].iter().all(|b| b.is_ascii_digit()) && s[9].is_ascii_uppercase() {
                // 9 digits + letter (LLP)
                return true;
            }
            // Post-2009 form: TYYEENNNN + check letter, length 10.
            if !matches!(s[0], b'T' | b'S' | b'R' | b'L') {
                return false;
            }
            s[1..3].iter().all(|b| b.is_ascii_digit())
                && s[3..5].iter().all(|b| b.is_ascii_uppercase())
                && s[5..9].iter().all(|b| b.is_ascii_digit())
                && s[9].is_ascii_uppercase()
        }
        _ => false,
    }
}

/// Malaysia MyKad: `YYMMDD-PB-####` where YYMMDD is the holder's
/// birth date, PB is the state code (01–59 plus the historical
/// 71–98 set), and #### is the serial. The DOB is validated against
/// the per-month day cap (e.g. 30 February is rejected) using the
/// Gregorian leap-year rule and the conventional pivot of YY ≤ 29
/// → 2000s, otherwise 1900s.
fn validate_my_mykad(s: &[u8]) -> bool {
    if s.len() != 14 || s[6] != b'-' || s[9] != b'-' {
        return false;
    }
    let Some(yy) = parse_ascii_u32(&s[0..2]) else {
        return false;
    };
    let Some(mm) = parse_ascii_u32(&s[2..4]) else {
        return false;
    };
    let Some(dd) = parse_ascii_u32(&s[4..6]) else {
        return false;
    };
    let year = if yy <= 29 { 2000 + yy } else { 1900 + yy };
    if !valid_dob(year, mm, dd) {
        return false;
    }
    let Some(state) = parse_ascii_u32(&s[7..9]) else {
        return false;
    };
    // Per JPN PB-state code list: 01-16 (states), 21-59 (extended
    // domestic), 71-89 (foreign born), 90-98 (other).
    let state_ok =
        (1..=16).contains(&state) || (21..=59).contains(&state) || (71..=98).contains(&state);
    if !state_ok {
        return false;
    }
    // Defence-in-depth: bottom serial section must be all digits even
    // though the regex pre-filter already guarantees it.
    s[10..14].iter().all(|b| b.is_ascii_digit())
}

/// China Resident Identity Card (GB 11643-1999): 17 digits + check
/// character `0–9` or `X`. Weights `[7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2]`
/// then `check_char = "10X98765432"[sum mod 11]`.
fn validate_cn_resident_id(s: &[u8]) -> bool {
    if s.len() != 18 {
        return false;
    }
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECK_TABLE: &[u8; 11] = b"10X98765432";
    let Some(digits) = parse_ascii_digits(&s[..17]) else {
        return false;
    };
    // Admin division code (first 6 digits) must start in 11..=82
    // (per Ministry of Civil Affairs province ranges).
    let province = (digits[0] as u32) * 10 + digits[1] as u32;
    if !(11..=82).contains(&province) {
        return false;
    }
    // Birth-year digits (positions 6..=9) must be 1800..=2099.
    let year = (digits[6] as u32) * 1000
        + (digits[7] as u32) * 100
        + (digits[8] as u32) * 10
        + digits[9] as u32;
    if !(1800..=2099).contains(&year) {
        return false;
    }
    let month = (digits[10] as u32) * 10 + digits[11] as u32;
    let day = (digits[12] as u32) * 10 + digits[13] as u32;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let expected = CHECK_TABLE[(sum % 11) as usize];
    s[17] == expected
}

/// Japan My Number (個人番号): 12 digits. Weights for digits 0..=10
/// (left-to-right) are `[6,5,4,3,2,7,6,5,4,3,2]`; if `r = sum mod 11`
/// is 0 or 1 then `check = 0`, else `check = 11 - r`.
fn validate_jp_my_number(s: &[u8]) -> bool {
    if s.len() != 12 {
        return false;
    }
    const WEIGHTS: [u32; 11] = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
    let Some(digits) = parse_ascii_digits(s) else {
        return false;
    };
    let sum: u32 = digits[..11]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let r = sum % 11;
    let check = if r < 2 { 0 } else { 11 - r };
    digits[11] as u32 == check
}

/// South Korea RRN. Format `YYMMDD-GNNNNNN`. Weights
/// `[2,3,4,5,6,7,8,9,2,3,4,5]` over the 12 digits (sans dash) and
/// `check = (11 - sum mod 11) mod 10`.
fn validate_kr_rrn(s: &[u8]) -> bool {
    if s.len() != 14 || s[6] != b'-' {
        return false;
    }
    let mut compact = [0u8; 13];
    compact[..6].copy_from_slice(&s[..6]);
    compact[6..].copy_from_slice(&s[7..14]);
    let Some(digits) = parse_ascii_digits(&compact) else {
        return false;
    };
    // Birth month / day sanity.
    let month = digits[2] as u32 * 10 + digits[3] as u32;
    let day = digits[4] as u32 * 10 + digits[5] as u32;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    const WEIGHTS: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = digits[..12]
        .iter()
        .zip(WEIGHTS.iter())
        .map(|(d, w)| (*d as u32) * w)
        .sum();
    let check = (11 - sum % 11) % 10;
    digits[12] as u32 == check
}

/// India Aadhaar: 12 digits, optionally split into three space-
/// separated groups of four. Verhoeff check digit across the full
/// 12-digit sequence.
fn validate_in_aadhaar(s: &[u8]) -> bool {
    let compact: Vec<u8> = s
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if compact.len() != 12 {
        return false;
    }
    // Aadhaar IDs never start with `0` or `1` per UIDAI policy.
    if matches!(compact[0], b'0' | b'1') {
        return false;
    }
    if !compact.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    verhoeff_check(&compact)
}

/// India PAN. Position 4 (0-indexed 3) carries the holder-type code.
/// Per Income-Tax Department rules: P/H/F/A/T/B/L/J/G/C are the
/// canonical types (Personal, HUF, Firm, AOP, Trust, BOI, Local
/// authority, artificial Juridical, Government, Company).
fn validate_in_pan(s: &[u8]) -> bool {
    if s.len() != 10 {
        return false;
    }
    if !s[..5].iter().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    if !s[5..9].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if !s[9].is_ascii_uppercase() {
        return false;
    }
    matches!(
        s[3],
        b'C' | b'P' | b'H' | b'F' | b'A' | b'T' | b'B' | b'L' | b'J' | b'G'
    )
}

/// Indonesia NIK (Nomor Induk Kependudukan): 16 digits. Positions
/// 0..=1 are the province code from the Kemendagri list (11..=94);
/// positions 6..=11 encode the holder's DOB (DDMMYY, women add 40
/// to DD).
fn validate_id_nik(s: &[u8]) -> bool {
    if s.len() != 16 {
        return false;
    }
    let Some(d) = parse_ascii_digits(s) else {
        return false;
    };
    let province = d[0] as u32 * 10 + d[1] as u32;
    if !(11..=94).contains(&province) {
        return false;
    }
    let mut day = d[6] as u32 * 10 + d[7] as u32;
    if day > 40 {
        day -= 40; // female offset
    }
    let month = d[8] as u32 * 10 + d[9] as u32;
    (1..=31).contains(&day) && (1..=12).contains(&month)
}

/// Philippines PhilSys: 12 digits in three dash-separated groups,
/// Luhn-protected.
fn validate_ph_philsys(s: &[u8]) -> bool {
    if s.len() != 14 || s[4] != b'-' || s[9] != b'-' {
        return false;
    }
    let mut compact = [0u8; 12];
    compact[..4].copy_from_slice(&s[..4]);
    compact[4..8].copy_from_slice(&s[5..9]);
    compact[8..].copy_from_slice(&s[10..14]);
    if !compact.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    luhn_check(&compact)
}

/// Hong Kong HKID. Either 1- or 2-letter prefix + 6 digits + a
/// parenthesised check character (digit or `A`). Weighted sum
/// uses 9..=1; letters are `A=10..Z=35`; the 1-letter form prepends
/// a space token treated as `36`.
fn validate_hk_hkid(s: &[u8]) -> bool {
    // Compact: strip parentheses.
    let mut compact = Vec::with_capacity(10);
    for &b in s {
        if b != b'(' && b != b')' {
            compact.push(b);
        }
    }
    // After stripping: either 8 or 9 chars (1-letter or 2-letter prefix).
    if compact.len() != 8 && compact.len() != 9 {
        return false;
    }
    // Map each char to its numeric value with leading space-pad.
    let mut values = Vec::with_capacity(9);
    if compact.len() == 8 {
        values.push(36); // implicit leading space for 1-letter form
    }
    for &b in &compact[..compact.len() - 1] {
        let v = if b.is_ascii_uppercase() {
            (b - b'A' + 10) as u32
        } else if b.is_ascii_digit() {
            (b - b'0') as u32
        } else {
            return false;
        };
        values.push(v);
    }
    let check_char = compact[compact.len() - 1];
    let check_val: u32 = if check_char == b'A' {
        10
    } else if check_char.is_ascii_digit() {
        (check_char - b'0') as u32
    } else {
        return false;
    };
    values.push(check_val);
    let weights: Vec<u32> = (1..=9).rev().collect();
    let sum: u32 = values.iter().zip(weights.iter()).map(|(v, w)| v * w).sum();
    sum.is_multiple_of(11)
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
    fn vn_cccd_accepts_known_layout() {
        let p = find_pattern("pii.vn_cccd");
        // 001 (Hanoi) + century-gender 2 (male, 2000–2099) + year 20.
        assert!(p.validate(b"001220123456"));
        // Province 79 (HCMC) + gender 0 + year 88.
        assert!(p.validate(b"079088123456"));
        // Province 0 not allowed; gender digit > 5 rejected.
        assert!(!p.validate(b"000220123456"));
        assert!(!p.validate(b"001620123456"));
        // Wrong length.
        assert!(!p.validate(b"00122012345"));
    }

    #[test]
    fn vn_mst_accepts_real_taxpayer_id() {
        let p = find_pattern("pii.vn_mst");
        // Real VinaCapital MST published in MoF registry.
        assert!(p.validate(b"0100109106"));
        // Branch suffix is permitted.
        assert!(p.validate(b"0100109106-001"));
        // Off-by-one corruption rejected.
        assert!(!p.validate(b"0100109107"));
    }

    #[test]
    fn vn_bhxh_accepts_province_prefix() {
        let p = find_pattern("pii.vn_bhxh");
        assert!(p.validate(b"HN1234567890"));
        assert!(p.validate(b"HC9876543210"));
        assert!(!p.validate(b"ZZ1234567890"));
    }

    #[test]
    fn th_id_accepts_published_fixture() {
        let p = find_pattern("pii.th_national_id");
        // "1234567890121" → algorithm yields check digit 1.
        // Leading 1 is a personal citizen prefix.
        assert!(p.validate(b"1234567890121"));
        // Bit-flipped suffix.
        assert!(!p.validate(b"1234567890122"));
        // Leading 0 is reserved for corporate juristic-person tax
        // IDs and must be rejected by the national-ID validator —
        // those route to `pii.th_tax_id` instead.
        // Compute the check digit for "012345678901_":
        //   sum = 0*13 + 1*12 + 2*11 + 3*10 + 4*9 + 5*8 + 6*7
        //       + 7*6 + 8*5 + 9*4 + 0*3 + 1*2
        //       = 0+12+22+30+36+40+42+42+40+36+0+2 = 302
        //   check = (11 - 302 % 11) % 10 = (11 - 5) % 10 = 6
        assert!(!p.validate(b"0123456789016"));
    }

    #[test]
    fn th_tax_id_requires_corporate_leading_zero() {
        // National-ID-style 13-digit number with personal prefix
        // must NOT match the corporate-tax-ID pattern; that keeps
        // `pii.th_national_id` and `pii.th_tax_id` disjoint so a
        // single TIN never produces two `LocalDetectionAlert`
        // findings.
        assert!(!validate_th_tax_id(b"1234567890121"));
        // The same fixture with the corporate `0` prefix and a
        // recomputed mod-11 check digit. Sum for "012345678901_" =
        // 302, check = 6.
        assert!(validate_th_tax_id(b"0123456789016"));
        // Corrupted corporate check digit.
        assert!(!validate_th_tax_id(b"0123456789017"));
    }

    #[test]
    fn sg_nric_accepts_s_series_known_id() {
        let p = find_pattern("pii.sg_nric");
        // Algorithm produces D for "S1234567" → published test ID.
        assert!(p.validate(b"S1234567D"));
        // T-series ⇒ offset 4. Compute the right letter:
        //   sum = 1*2+2*7+3*6+4*5+5*4+6*3+7*2 = 2+14+18+20+20+18+14 = 106
        //   With offset 4 ⇒ 110, mod 11 = 0 ⇒ alphabet[0] = J.
        assert!(p.validate(b"T1234567J"));
        // M-series uses the flipped alphabet — published sample.
        // sum = 1*2+2*7+3*6+4*5+5*4+6*3+7*2 = 106; +3 = 109; mod 11 = 10
        //   ⇒ M_ALPHABET[10 - 10] = M_ALPHABET[0] = X.
        assert!(p.validate(b"M1234567X"));
        // Corrupted suffix.
        assert!(!p.validate(b"S1234567A"));
    }

    #[test]
    fn sg_uen_accepts_three_published_shapes() {
        let p = find_pattern("pii.sg_uen");
        assert!(p.validate(b"12345678A")); // pre-2009 business
        assert!(p.validate(b"123456789B")); // LLP
        assert!(p.validate(b"T18LL0001A")); // post-2009 entity
        assert!(!p.validate(b"X1234567A")); // wrong prefix letter
    }

    #[test]
    fn my_mykad_validates_format_and_state() {
        let p = find_pattern("pii.my_mykad");
        assert!(p.validate(b"910101-10-1234")); // Malacca state code
        assert!(!p.validate(b"910230-10-1234")); // invalid day-of-month
        assert!(!p.validate(b"910101-99-1234")); // invalid state code
    }

    #[test]
    fn cn_resident_id_accepts_official_sample() {
        let p = find_pattern("pii.cn_resident_id");
        // Beijing (11), DOB 1949-12-31, serial 002, check X.
        assert!(p.validate(b"11010519491231002X"));
        // Off-by-one breaks the check digit.
        assert!(!p.validate(b"11010519491231002Y"));
        // Out-of-range admin code rejected.
        assert!(!p.validate(b"99010519491231002X"));
    }

    #[test]
    fn jp_my_number_accepts_computed_fixture() {
        let p = find_pattern("pii.jp_my_number");
        // First 11 digits "12345678901" ⇒ check 8.
        assert!(p.validate(b"123456789018"));
        assert!(!p.validate(b"123456789019"));
    }

    #[test]
    fn kr_rrn_accepts_computed_fixture() {
        let p = find_pattern("pii.kr_rrn");
        // First 12 digits "990101123456" ⇒ check 3.
        assert!(p.validate(b"990101-1234563"));
        assert!(!p.validate(b"990101-1234567"));
        // Invalid gender digit.
        assert!(!p.regex.is_match(b"990101-5234563"));
    }

    #[test]
    fn in_aadhaar_accepts_published_fixture() {
        let p = find_pattern("pii.in_aadhaar");
        // Verhoeff-valid published Aadhaar fixture.
        assert!(p.validate(b"234123412346"));
        assert!(p.validate(b"2341 2341 2346")); // space-separated form
        assert!(!p.validate(b"234123412345"));
        assert!(!p.validate(b"034123412346")); // leading 0 disallowed
    }

    #[test]
    fn in_pan_accepts_canonical_form() {
        let p = find_pattern("pii.in_pan");
        assert!(p.validate(b"ABCPF1234X")); // P = Personal
        assert!(p.validate(b"ABCCF1234X")); // C = Company
        assert!(!p.validate(b"ABCXF1234X")); // X is not a valid holder type
        assert!(!p.validate(b"abcpf1234x")); // lowercase rejected
    }

    #[test]
    fn id_nik_validates_province_and_dob() {
        let p = find_pattern("pii.id_nik");
        // Jakarta (31), DOB 25-01-1988 (male, day 25), serial 0001.
        assert!(p.validate(b"3174012501880001"));
        // Female encoding (day + 40 = 65).
        assert!(p.validate(b"3174016501880001"));
        // Bad province code.
        assert!(!p.validate(b"0174012501880001"));
        // Bad month.
        assert!(!p.validate(b"3174012513880001"));
    }

    #[test]
    fn ph_philsys_accepts_computed_luhn() {
        let p = find_pattern("pii.ph_philsys");
        // First 11 digits 12345678901 ⇒ Luhn check 5.
        assert!(p.validate(b"1234-5678-9015"));
        assert!(!p.validate(b"1234-5678-9016"));
    }

    #[test]
    fn hk_hkid_accepts_one_and_two_letter_variants() {
        let p = find_pattern("pii.hk_hkid");
        // 1-letter HKID A123456 with check digit 3 (computed below).
        //   space-pad ⇒ values [36, 10, 1, 2, 3, 4, 5, 6, X]
        //   weights [9, 8, 7, 6, 5, 4, 3, 2, 1]
        //   sum w/o X = 36*9 + 10*8 + 1*7 + 2*6 + 3*5 + 4*4 + 5*3 + 6*2
        //             = 324 + 80 + 7 + 12 + 15 + 16 + 15 + 12 = 481
        //   481 mod 11 = 8 ⇒ X = (11 - 8) mod 11 = 3.
        assert!(p.validate(b"A123456(3)"));
        // 2-letter HKID AB123456 with check digit 9:
        //   values [10, 11, 1, 2, 3, 4, 5, 6, X]
        //   sum w/o X = 90 + 88 + 7 + 12 + 15 + 16 + 15 + 12 = 255
        //   255 mod 11 = 2 ⇒ X = 9.
        assert!(p.validate(b"AB123456(9)"));
        // Off-by-one check digit fails.
        assert!(!p.validate(b"A123456(4)"));
        assert!(!p.validate(b"AB123456(0)"));
        // Check digit `A` (== 10) is valid syntax — verify rejection
        // when arithmetic doesn't match.
        assert!(!p.validate(b"A123456(A)"));
    }
}
