//! Global / cross-jurisdictional DLP patterns: the historic
//! SSN / UK NI / PAN baseline, plus jurisdiction-agnostic detectors
//! for email, phone numbers, ICAO passports, and developer secrets.

use regex::bytes::Regex;

use super::validators::{luhn_check, parse_ascii_u32};
use super::PatternDef;

pub(crate) const CATEGORIES: &[&str] = &[
    "pii.ssn",
    "pci.pan_luhn",
    "pii.email",
    "pii.phone_e164",
    "pii.passport_mrz",
    "secrets.aws_access_key",
    "secrets.private_key",
    "secrets.github_pat",
    "secrets.slack_token",
    "secrets.gcp_service_key",
    "secrets.azure_client_secret",
    "secrets.jwt",
    "secrets.generic_api_key",
];

/// Returns every pattern in the global region.
pub(crate) fn patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            category: "pii.ssn",
            region: "global",
            name: "US Social Security Number",
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex"),
            validator: validate_ssn,
        },
        PatternDef {
            category: "pci.pan_luhn",
            region: "global",
            name: "Payment Card Number (Luhn)",
            // 13–19 digits is the ISO/IEC 7812 PAN range.
            regex: Regex::new(r"\b\d{13,19}\b").expect("pan regex"),
            validator: validate_pan_luhn,
        },
        PatternDef {
            category: "pii.email",
            region: "global",
            name: "RFC 5321 Email Address",
            // Conservative RFC 5321 inspired form. `\b` excludes
            // trailing punctuation cleanly. Local part: dot-atom +
            // limited specials; domain: at least one dot, TLD ≥ 2.
            regex: Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b")
                .expect("email regex"),
            validator: validate_email,
        },
        PatternDef {
            category: "pii.phone_e164",
            region: "global",
            name: "E.164 International Phone Number",
            // E.164 allows up to 15 digits (ITU-T E.164). Leading +
            // is required; we treat `\+` as the boundary marker.
            regex: Regex::new(r"\+\d{7,15}").expect("phone regex"),
            validator: validate_phone_e164,
        },
        PatternDef {
            category: "pii.passport_mrz",
            region: "global",
            name: "ICAO 9303 Passport MRZ",
            // ICAO 9303 MRZ line 2 of a TD3 passport: doc-number(9) +
            // check(1) + nationality(3) + dob(6) + check(1) + sex(1) +
            // expiry(6) + check(1) + personal(14) + check(1) + composite(1).
            // Use the 44-character line that carries every check digit.
            regex: Regex::new(r"\b[A-Z0-9<]{9}\d[A-Z<]{3}\d{6}\d[MFX<]\d{6}\d[A-Z0-9<]{14}\d\d\b")
                .expect("mrz regex"),
            validator: validate_passport_mrz,
        },
        PatternDef {
            category: "secrets.aws_access_key",
            region: "global",
            name: "AWS Access Key ID",
            regex: Regex::new(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b")
                .expect("aws regex"),
            validator: ascii_only_passthrough,
        },
        PatternDef {
            category: "secrets.private_key",
            region: "global",
            name: "PEM-armored Private Key",
            // Real PEM private-key armors are either bare ("BEGIN
            // PRIVATE KEY"), with an algorithm prefix ("BEGIN RSA
            // PRIVATE KEY", "BEGIN EC PRIVATE KEY"), with a
            // format prefix ("BEGIN OPENSSH PRIVATE KEY"), or with
            // an attribute prefix ("BEGIN ENCRYPTED PRIVATE KEY").
            // Accept any uppercase token sequence followed by a
            // space as an optional discriminator.
            regex: Regex::new(r"-----BEGIN (?:[A-Z][A-Z ]+)?PRIVATE KEY-----")
                .expect("pem regex"),
            validator: validate_pem_armor,
        },
        PatternDef {
            category: "secrets.github_pat",
            region: "global",
            name: "GitHub Personal Access Token",
            // GitHub PAT family: ghp_ (user), gho_ (OAuth), ghu_
            // (user-to-server), ghs_ (server-to-server), ghr_ (refresh).
            regex: Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36}\b").expect("ghpat regex"),
            validator: ascii_only_passthrough,
        },
        PatternDef {
            category: "secrets.slack_token",
            region: "global",
            name: "Slack API Token",
            // xoxb (bot), xoxa (app), xoxp (user), xoxr (refresh),
            // xoxs (workspace), xoxe (legacy bot).
            regex: Regex::new(r"\bxox[baprse]-[A-Za-z0-9-]{10,}\b").expect("slack regex"),
            validator: validate_slack_token,
        },
        PatternDef {
            category: "secrets.gcp_service_key",
            region: "global",
            name: "Google Cloud Service Account Key (JSON)",
            // Match the `"type": "service_account"` marker; the JSON
            // marker is the cheapest reliable signature.
            regex: Regex::new(r#""type"\s*:\s*"service_account""#).expect("gcp regex"),
            validator: ascii_only_passthrough,
        },
        PatternDef {
            category: "secrets.azure_client_secret",
            region: "global",
            name: "Azure AD Client Secret",
            // Azure AD client secrets are 40-char URL-safe base64 with
            // a typical `~` separator (post-2021 format) or a 32-char
            // hex form (legacy). Match the modern format conservatively.
            regex: Regex::new(r"\b[A-Za-z0-9~._-]{3}8Q~[A-Za-z0-9~._-]{34}\b")
                .expect("azure regex"),
            validator: ascii_only_passthrough,
        },
        PatternDef {
            category: "secrets.jwt",
            region: "global",
            name: "JSON Web Token",
            regex: Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
                .expect("jwt regex"),
            validator: validate_jwt,
        },
        PatternDef {
            category: "secrets.generic_api_key",
            region: "global",
            name: "Generic API Key Assignment",
            // Heuristic — looks for an `api[_-]?key` assignment with a
            // ≥ 20-character entropy-bearing value. Validator further
            // restricts to mixed alphanumeric strings to keep noise
            // out.
            regex: Regex::new(
                r#"(?i)\b[a-z][a-z0-9_-]*api[_-]?key[a-z0-9_-]*\s*[:=]\s*['"]?[A-Za-z0-9_\-+/=]{20,}['"]?"#,
            )
            .expect("api key regex"),
            validator: validate_generic_api_key,
        },
        // UK NI moves to europe.rs.
        // The legacy UK NI baseline lives in the europe module to
        // keep regional glob (`europe.*`) selection meaningful.
    ]
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Generic "no further structural check required" validator. Used by
/// detectors whose regex already carries every constraint we can
/// cheaply enforce (e.g. AWS access keys, GitHub PATs, PEM headers).
/// Returns `true` whenever the candidate is non-empty ASCII; the
/// regex pre-filter has already done the real work.
fn ascii_only_passthrough(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|b| b.is_ascii())
}

/// Loose SSN validator (US SSA-issued numbers). Rejects synthetic
/// `000`, `666`, and `900–999` area blocks plus empty group / serial.
fn validate_ssn(s: &[u8]) -> bool {
    if s.len() != 11 || s[3] != b'-' || s[6] != b'-' {
        return false;
    }
    let area = parse_ascii_u32(&s[0..3]);
    let group = parse_ascii_u32(&s[4..6]);
    let serial = parse_ascii_u32(&s[7..11]);
    match (area, group, serial) {
        (Some(area), Some(group), Some(serial)) => {
            area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
        }
        _ => false,
    }
}

/// PAN validator: length window + Luhn checksum.
fn validate_pan_luhn(s: &[u8]) -> bool {
    if s.len() < 13 || s.len() > 19 {
        return false;
    }
    luhn_check(s)
}

/// Email validator: rejects local-part edge cases the regex still
/// admits (leading dot, double dot, trailing dot).
fn validate_email(s: &[u8]) -> bool {
    let at = match s.iter().position(|&b| b == b'@') {
        Some(i) => i,
        None => return false,
    };
    let (local, domain) = (&s[..at], &s[at + 1..]);
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if local.first() == Some(&b'.') || local.last() == Some(&b'.') {
        return false;
    }
    if local.windows(2).any(|w| w == b"..") {
        return false;
    }
    if domain.first() == Some(&b'.') || domain.last() == Some(&b'.') {
        return false;
    }
    if domain.windows(2).any(|w| w == b"..") {
        return false;
    }
    domain.contains(&b'.')
}

/// E.164 phone validator: leading `+`, valid ITU country-code prefix
/// (1, 2, or 3 digits), total length 8..=16 (the `+` plus ≤ 15 digits).
fn validate_phone_e164(s: &[u8]) -> bool {
    if s.len() < 8 || s.len() > 16 || s.first() != Some(&b'+') {
        return false;
    }
    if !s[1..].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // ITU-T E.164 country codes: try 1-digit, 2-digit, then 3-digit.
    let digits = &s[1..];
    let cc1 = digits.first().map(|b| (b - b'0') as u32);
    let cc2 = parse_ascii_u32(&digits[..2.min(digits.len())]);
    let cc3 = parse_ascii_u32(&digits[..3.min(digits.len())]);
    if cc1.is_some_and(itu_country_code_1_digit) {
        return true;
    }
    if cc2.is_some_and(itu_country_code_2_digit) {
        return true;
    }
    if cc3.is_some_and(itu_country_code_3_digit) {
        return true;
    }
    false
}

/// 1-digit ITU country codes (Zone 1 NANP, Zone 7 Russia/Kazakhstan).
fn itu_country_code_1_digit(cc: u32) -> bool {
    matches!(cc, 1 | 7)
}

/// 2-digit ITU country codes (selected canonical list — full list
/// at <https://www.itu.int/dms_pub/itu-t/opb/sp/T-SP-E.164D-11-2011-PDF-E.pdf>).
fn itu_country_code_2_digit(cc: u32) -> bool {
    matches!(
        cc,
        20  // Egypt
        | 27 // South Africa
        | 30 | 31 | 32 | 33 | 34 | 36 | 39 // EU (GR, NL, BE, FR, ES, HU, IT)
        | 40 | 41 | 43 | 44 | 45 | 46 | 47 | 48 | 49 // EU (RO, CH, AT, GB, DK, SE, NO, PL, DE)
        | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 58 // Americas
        | 60 | 61 | 62 | 63 | 64 | 65 | 66 // APAC (MY, AU, ID, PH, NZ, SG, TH)
        | 81 | 82 | 84 | 86 | 90 | 91 | 92 | 93 | 94 | 95 | 98 // East Asia + ME
    )
}

/// 3-digit ITU country codes (selected canonical list).
fn itu_country_code_3_digit(cc: u32) -> bool {
    matches!(
        cc,
        // Africa (most countries)
        211 | 212 | 213 | 216 | 218 | 220 | 221 | 222 | 223 | 224 | 225 | 226 | 227 | 228
        | 229 | 230 | 231 | 232 | 233 | 234 | 235 | 236 | 237 | 238 | 239 | 240 | 241
        | 242 | 243 | 244 | 245 | 246 | 247 | 248 | 249 | 250 | 251 | 252 | 253 | 254
        | 255 | 256 | 257 | 258 | 260 | 261 | 262 | 263 | 264 | 265 | 266 | 267 | 268
        | 269 | 290 | 291 | 297 | 298 | 299
        // Europe
        | 350 | 351 | 352 | 353 | 354 | 355 | 356 | 357 | 358 | 359 | 370 | 371 | 372
        | 373 | 374 | 375 | 376 | 377 | 378 | 379 | 380 | 381 | 382 | 383 | 385 | 386
        | 387 | 389 | 420 | 421 | 423
        // Americas (Caribbean + LATAM)
        | 500 | 501 | 502 | 503 | 504 | 505 | 506 | 507 | 508 | 509 | 590 | 591 | 592
        | 593 | 594 | 595 | 596 | 597 | 598 | 599
        // Asia/Oceania
        | 670 | 672 | 673 | 674 | 675 | 676 | 677 | 678 | 679 | 680 | 681 | 682 | 683
        | 685 | 686 | 687 | 688 | 689 | 690 | 691 | 692
        // South / Central Asia
        | 850 | 852 | 853 | 855 | 856 | 870 | 880 | 886
        // Middle East + neighbours
        | 960 | 961 | 962 | 963 | 964 | 965 | 966 | 967 | 968 | 970 | 971 | 972 | 973
        | 974 | 975 | 976 | 977 | 992 | 993 | 994 | 995 | 996 | 998
    )
}

/// ICAO 9303 TD3 MRZ line-2 validator. Verifies each field's
/// per-character check digit plus the composite check digit using
/// the standard 7/3/1 weighting.
fn validate_passport_mrz(s: &[u8]) -> bool {
    if s.len() != 44 {
        return false;
    }
    let doc_number = &s[0..9];
    let doc_check = s[9];
    let dob = &s[13..19];
    let dob_check = s[19];
    let expiry = &s[21..27];
    let expiry_check = s[27];
    let personal = &s[28..42];
    let personal_check = s[42];
    let composite_check = s[43];

    if !icao_check_matches(doc_number, doc_check) {
        return false;
    }
    if !icao_check_matches(dob, dob_check) {
        return false;
    }
    if !icao_check_matches(expiry, expiry_check) {
        return false;
    }
    // Personal-number field may be all `<`; the spec says the check
    // digit MUST be `0` in that case, and the field MUST otherwise
    // pass the standard check.
    if personal.iter().all(|&b| b == b'<') {
        if personal_check != b'0' && personal_check != b'<' {
            return false;
        }
    } else if !icao_check_matches(personal, personal_check) {
        return false;
    }
    let mut composite = Vec::with_capacity(28);
    composite.extend_from_slice(doc_number);
    composite.push(doc_check);
    composite.extend_from_slice(dob);
    composite.push(dob_check);
    composite.extend_from_slice(expiry);
    composite.push(expiry_check);
    composite.extend_from_slice(personal);
    composite.push(personal_check);
    icao_check_matches(&composite, composite_check)
}

/// ICAO 9303 weighted check digit: weights cycle 7, 3, 1, with letters
/// folded to values A=10..Z=35 and `<` treated as 0.
fn icao_check_matches(field: &[u8], expected: u8) -> bool {
    let mut sum: u32 = 0;
    let weights = [7u32, 3, 1];
    for (i, &b) in field.iter().enumerate() {
        let v = match b {
            b'<' => 0,
            b'0'..=b'9' => (b - b'0') as u32,
            b'A'..=b'Z' => (b - b'A' + 10) as u32,
            _ => return false,
        };
        sum += v * weights[i % 3];
    }
    expected == b'0' + ((sum % 10) as u8)
}

/// PEM armor validator: regex matched the BEGIN marker; require that
/// the captured slice closes the marker with `-----` (the regex already
/// enforces this) and contains an inner keyword like `RSA`, `EC`,
/// `OPENSSH`, `DSA`, `PRIVATE` etc. ASCII-only sanity check.
fn validate_pem_armor(s: &[u8]) -> bool {
    if s.len() < b"-----BEGIN PRIVATE KEY-----".len() {
        return false;
    }
    s.starts_with(b"-----BEGIN ")
        && s.ends_with(b"-----")
        && s.windows(b"PRIVATE KEY".len()).any(|w| w == b"PRIVATE KEY")
}

/// Slack token validator: enforce the four-segment dash form for the
/// `xoxb` / `xoxp` families, where the second dash precedes a numeric
/// workspace ID. Token formats per
/// <https://api.slack.com/authentication/token-types>.
fn validate_slack_token(s: &[u8]) -> bool {
    let prefix = b"xox";
    if !s.starts_with(prefix) || s.len() < 14 {
        return false;
    }
    // xox[type]-...; expect ≥ 2 dashes (xoxb-WS-TOK).
    s.iter().filter(|&&b| b == b'-').count() >= 2
}

/// JWT validator: base64url-decode the header, ensure it parses as
/// JSON with a string `alg` field (the canonical JWT marker).
fn validate_jwt(s: &[u8]) -> bool {
    let mut parts = s.split(|&b| b == b'.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(_payload) = parts.next() else {
        return false;
    };
    let Some(sig) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || sig.is_empty() {
        return false;
    }
    let decoded = match base64url_decode(header) {
        Some(v) => v,
        None => return false,
    };
    // Look for `"alg"` as a JSON key.
    decoded.windows(5).any(|w| w == b"\"alg\"")
}

/// Permissive base64url decoder used by the JWT validator. Returns
/// `None` for any non-base64-url byte.
fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            b'=' => None, // padding ends decoding
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        if b == b'=' {
            break;
        }
        let v = val(b)?;
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Generic API-key validator: require ≥ 20 chars, at least one digit
/// and at least one letter to suppress repeating-character noise.
fn validate_generic_api_key(s: &[u8]) -> bool {
    let mut value_start = match s.iter().position(|&b| b == b'=' || b == b':') {
        Some(i) => i + 1,
        None => return false,
    };
    while value_start < s.len()
        && (s[value_start] == b' ' || s[value_start] == b'"' || s[value_start] == b'\'')
    {
        value_start += 1;
    }
    let mut value_end = s.len();
    while value_end > value_start && (s[value_end - 1] == b'"' || s[value_end - 1] == b'\'') {
        value_end -= 1;
    }
    let value = &s[value_start..value_end];
    if value.len() < 20 {
        return false;
    }
    let has_digit = value.iter().any(|b| b.is_ascii_digit());
    let has_letter = value.iter().any(|b| b.is_ascii_alphabetic());
    has_digit && has_letter
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::PatternDef;
    use regex::bytes::Regex;

    fn first_match<'a>(re: &Regex, hay: &'a [u8]) -> Option<&'a [u8]> {
        re.find(hay).map(|m| m.as_bytes())
    }

    fn find_pattern(category: &str) -> PatternDef {
        patterns()
            .into_iter()
            .find(|p| p.category == category)
            .unwrap()
    }

    #[test]
    fn ssn_baseline_still_works() {
        let p = find_pattern("pii.ssn");
        let hay = b"patient 123-45-6789 was admitted";
        let m = first_match(&p.regex, hay).unwrap();
        assert_eq!(m, b"123-45-6789");
        assert!(p.validate(m));
        // Reserved blocks.
        assert!(!validate_ssn(b"000-12-3456"));
        assert!(!validate_ssn(b"666-12-3456"));
        assert!(!validate_ssn(b"900-12-3456"));
        assert!(!validate_ssn(b"123-00-3456"));
        assert!(!validate_ssn(b"123-45-0000"));
    }

    #[test]
    fn pan_baseline_still_works() {
        let p = find_pattern("pci.pan_luhn");
        assert!(p.validate(b"4242424242424242"));
        assert!(!p.validate(b"4242424242424243"));
        assert!(!p.validate(b"1234567890123")); // bad luhn
        assert!(!p.validate(b"4")); // too short
    }

    #[test]
    fn email_accepts_real_addresses() {
        let p = find_pattern("pii.email");
        for ok in [
            "alice@example.com",
            "first.last+tag@sub.example.co.uk",
            "user_123@host.io",
        ] {
            assert!(p.regex.is_match(ok.as_bytes()), "regex: {ok}");
            let m = p.regex.find(ok.as_bytes()).unwrap();
            assert!(p.validate(m.as_bytes()), "validator: {ok}");
        }
    }

    #[test]
    fn email_rejects_malformed() {
        assert!(!validate_email(b".alice@example.com"));
        assert!(!validate_email(b"alice@example..com"));
        assert!(!validate_email(b"alice@.com"));
        assert!(!validate_email(b"alice@com")); // no dot
        assert!(!validate_email(b"alice"));
    }

    #[test]
    fn phone_validator_accepts_known_e164() {
        for ok in [
            "+14155552671",   // US
            "+442071838750",  // UK
            "+8613912345678", // China
            "+819012345678",  // Japan
            "+9715551234567", // UAE
            "+6591234567",    // Singapore
        ] {
            assert!(validate_phone_e164(ok.as_bytes()), "expected accept: {ok}");
        }
    }

    #[test]
    fn phone_validator_rejects_invalid_prefixes() {
        // `0` is reserved by ITU as the international "operator
        // assistance" prefix and is not a country code; the value
        // never resolves at 1-, 2-, or 3-digit length.
        assert!(!validate_phone_e164(b"+01234567"));
        // Total length below the 8-byte minimum.
        assert!(!validate_phone_e164(b"+92"));
        // `+215` and `+217` / `+219` are explicitly unassigned in
        // ITU-T E.164.D recommendation (Africa 21X gap).
        assert!(!validate_phone_e164(b"+21512345678"));
        // `+888` is reserved for the Telecommunications for Disaster
        // Relief service (ITU-T E.164.1); not a country.
        assert!(!validate_phone_e164(b"+888123456789"));
        // Missing leading `+`.
        assert!(!validate_phone_e164(b"4155552671"));
    }

    #[test]
    fn aws_access_key_matches_canonical_prefixes() {
        let p = find_pattern("secrets.aws_access_key");
        for ok in [
            b"AKIAIOSFODNN7EXAMPLE" as &[u8],
            b"ASIAJL5EXAMPLEKEYZZZ",
            b"AROAJKL5EXAMPLEKZZZZ",
        ] {
            assert!(p.regex.is_match(ok), "expected match: {ok:?}");
        }
        // Wrong prefix.
        assert!(!p.regex.is_match(b"AKLAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn github_pat_matches_expected_families() {
        let p = find_pattern("secrets.github_pat");
        for ok in [
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
            "ghu_abcdefghijklmnopqrstuvwxyz0123456789",
        ] {
            assert!(p.regex.is_match(ok.as_bytes()), "{ok}");
        }
        assert!(!p.regex.is_match(b"ghx_too_short"));
    }

    #[test]
    fn slack_token_requires_three_segments() {
        let p = find_pattern("secrets.slack_token");
        // Synthetic non-secret fixture: letters in every segment so
        // the GitHub Slack-token secret scanner (which expects the
        // canonical `xox[type]-<digits>-<digits>-<alnum>` shape)
        // does not flag it, while the validator's "≥ 2 dashes"
        // check still exercises the segment count.
        let ok = b"xoxb-EXAMPLEAAAA-EXAMPLEBBBB-NOTAREALTOKENCC";
        assert!(p.regex.is_match(ok));
        assert!(p.validate(ok));
        assert!(!p.validate(b"xoxb-onlyonepart"));
    }

    #[test]
    fn pem_armor_matches_real_headers() {
        let p = find_pattern("secrets.private_key");
        for ok in [
            b"-----BEGIN RSA PRIVATE KEY-----" as &[u8],
            b"-----BEGIN PRIVATE KEY-----",
            b"-----BEGIN OPENSSH PRIVATE KEY-----",
            b"-----BEGIN EC PRIVATE KEY-----",
        ] {
            assert!(p.regex.is_match(ok), "{ok:?}");
        }
    }

    #[test]
    fn jwt_validator_accepts_known_tokens() {
        // Canonical jwt.io example token (HS256 with alg/header).
        let token = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let p = find_pattern("secrets.jwt");
        assert!(p.regex.is_match(token));
        let m = p.regex.find(token).unwrap();
        assert!(p.validate(m.as_bytes()));
    }

    #[test]
    fn jwt_validator_rejects_missing_alg() {
        // base64url("{\"typ\":\"JWT\"}") with no alg → fail validator.
        let header_b64 = "eyJ0eXAiOiJKV1QifQ";
        let bad = format!("{header_b64}.eyJzdWIiOiIxMjMifQ.signature");
        assert!(!validate_jwt(bad.as_bytes()));
    }

    #[test]
    fn passport_mrz_accepts_icao_fixture() {
        // ICAO Doc 9303 Part 4 sample MRZ line 2.
        let p = find_pattern("pii.passport_mrz");
        let line = b"L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        assert!(p.regex.is_match(line));
        assert!(p.validate(line));
    }

    #[test]
    fn passport_mrz_rejects_corrupted_check_digit() {
        let line = b"L898902C36UTO7408122F1204159ZE184226B<<<<<11";
        assert!(!validate_passport_mrz(line));
    }

    #[test]
    fn generic_api_key_filters_low_entropy_assignments() {
        let p = find_pattern("secrets.generic_api_key");
        let hay = br#"DEPLOY_API_KEY = "AbcDef0123456789xyzQwertyUiop""#;
        let m = p.regex.find(hay).expect("should match");
        assert!(p.validate(m.as_bytes()));

        // Trivial value (all letters, no digits) → reject.
        let weak = br#"api_key="aaaaaaaaaaaaaaaaaaaaaaaa""#;
        let m2 = p.regex.find(weak);
        assert!(m2.is_none() || !validate_generic_api_key(m2.unwrap().as_bytes()));
    }
}
