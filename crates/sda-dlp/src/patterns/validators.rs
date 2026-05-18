//! Shared check-digit and structural validators used across the
//! regional DLP pattern modules.
//!
//! Each helper operates on raw ASCII byte slices and never allocates
//! intermediate `String`s. The regex pre-filters in
//! [`crate::patterns::baseline_patterns`] only ever surface ASCII
//! candidates, so callers can rely on these helpers rejecting any
//! non-ASCII byte rather than mis-interpreting it.

/// Parse a fixed-length ASCII decimal slice into a `u32`. Returns
/// `None` if any byte is not an ASCII digit or the value would
/// overflow.
pub(crate) fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(acc)
}

/// Decode an ASCII decimal slice into a digit-value vector (0–9).
/// Returns `None` on any non-digit byte. Used by validators that need
/// per-position arithmetic.
pub(crate) fn parse_ascii_digits(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out.push(b - b'0');
    }
    Some(out)
}

/// Luhn (mod-10) check over an ASCII digit string. Returns `false`
/// for empty input — an empty buffer is never a valid PAN.
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

/// ISO 7064 mod-97-10 check used by every IBAN.
///
/// `iban` must be the canonical IBAN form (uppercase ASCII, no spaces,
/// 5–34 characters). Letters convert to two-digit numbers A=10..Z=35
/// before the running mod-97 is computed; the algorithm rearranges
/// the first four characters to the end before scanning.
pub fn mod97_check(iban: &[u8]) -> bool {
    if iban.len() < 5 || iban.len() > 34 {
        return false;
    }
    if !iban.iter().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let mut remainder: u32 = 0;
    let rotated = iban[4..].iter().chain(iban[..4].iter());
    for &b in rotated {
        let value: u32 = if b.is_ascii_digit() {
            (b - b'0') as u32
        } else if b.is_ascii_uppercase() {
            (b - b'A' + 10) as u32
        } else {
            return false;
        };
        if value >= 10 {
            remainder = (remainder * 100 + value) % 97;
        } else {
            remainder = (remainder * 10 + value) % 97;
        }
    }
    remainder == 1
}

/// Verhoeff check-digit algorithm used by India Aadhaar.
///
/// The last digit of `digits` is the embedded check; the algorithm
/// returns `true` when the running state collapses to zero after
/// folding every digit through the `d`/`p` tables.
pub fn verhoeff_check(digits: &[u8]) -> bool {
    static D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    static P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    if digits.is_empty() {
        return false;
    }
    let mut c: usize = 0;
    for (i, &b) in digits.iter().rev().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        let d = (b - b'0') as usize;
        c = D[c][P[i % 8][d] as usize] as usize;
    }
    c == 0
}

/// Generic weighted mod-11 check. Returns `true` when the weighted
/// sum of `digits` (zipped with `weights`) is congruent to 0 mod 11.
///
/// `weights` must have the same length as `digits`.
pub fn mod11_check(digits: &[u8], weights: &[u32]) -> bool {
    if digits.len() != weights.len() || digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &b) in digits.iter().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        sum = sum.saturating_add((b - b'0') as u32 * weights[i]);
    }
    sum.is_multiple_of(11)
}

/// Compute `sum(digit_i * weight_i) mod modulus`. Returns `None` on a
/// length mismatch, zero modulus, or any non-digit byte.
pub fn weighted_checksum(digits: &[u8], weights: &[u32], modulus: u32) -> Option<u32> {
    if digits.len() != weights.len() || modulus == 0 {
        return None;
    }
    let mut sum: u32 = 0;
    for (i, &b) in digits.iter().enumerate() {
        if !b.is_ascii_digit() {
            return None;
        }
        sum = sum.saturating_add((b - b'0') as u32 * weights[i]);
    }
    Some(sum % modulus)
}

/// EAN-13 check digit (used by the Swiss AHV/AVS new-format number).
/// The 13th digit must close the standard EAN-13 weighted sum to zero
/// mod 10.
pub fn ean13_check(digits: &[u8]) -> bool {
    if digits.len() != 13 {
        return false;
    }
    let mut sum: u32 = 0;
    for (i, &b) in digits.iter().enumerate() {
        if !b.is_ascii_digit() {
            return false;
        }
        let d = (b - b'0') as u32;
        let w = if i % 2 == 0 { 1 } else { 3 };
        sum += d * w;
    }
    sum.is_multiple_of(10)
}

/// ISO 7064 mod-11,10 check used by Germany's 11-digit Steuer-IdNr.
/// The 11th digit is the check; the first 10 are validated against
/// the iterative `(d + product) mod 10 → s, (s*2) mod 11 → product`
/// recurrence.
pub fn iso7064_mod11_10(digits: &[u8]) -> bool {
    if digits.len() != 11 || !digits.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut product: u32 = 10;
    for &b in &digits[..10] {
        let d = (b - b'0') as u32;
        let mut s = (d + product) % 10;
        if s == 0 {
            s = 10;
        }
        product = (s * 2) % 11;
    }
    let check = (11 - product) % 10;
    (digits[10] - b'0') as u32 == check
}

/// Gregorian leap-year rule used by the Asia / GCC DOB-bearing IDs.
/// Pure arithmetic; no chrono dependency.
pub fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Maximum valid day-of-month for the given (year, month) pair.
/// Returns `0` for an out-of-range `month`. Year is the full
/// 4-digit Gregorian year; callers that hold a 2-digit `yy` resolve
/// the century before calling.
pub fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Validate a (year, month, day) calendar triple. Year/month/day
/// must each fit the Gregorian range and the day must be ≤ the
/// month's last day for the supplied year.
pub fn valid_dob(year: u32, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    day <= days_in_month(year, month)
}

/// Structural rule for Germany Steuer-IdNr: in the leading 10 digits
/// exactly one digit must repeat. The legacy form (issued through
/// 2015) has one digit appearing twice and one digit absent. The
/// post-2016 form admits one digit appearing three times, in which
/// case the digit sum forces exactly two digits to be absent (counts
/// sum to 10, so `3 + 7 = 10` ⇒ 2 zeros). Anything else — including
/// a digit appearing four or more times — is structurally invalid.
pub fn de_steuer_id_structure(digits: &[u8]) -> bool {
    if digits.len() < 10 {
        return false;
    }
    let mut counts = [0u8; 10];
    for &b in &digits[..10] {
        if !b.is_ascii_digit() {
            return false;
        }
        counts[(b - b'0') as usize] += 1;
    }
    let zeros = counts.iter().filter(|&&c| c == 0).count();
    let twos = counts.iter().filter(|&&c| c == 2).count();
    let threes = counts.iter().filter(|&&c| c == 3).count();
    let overflow = counts.iter().filter(|&&c| c > 3).count();
    if overflow != 0 {
        return false;
    }
    // Exactly one digit repeats. Either it's the legacy 2× form
    // (one absent digit), or the post-2016 3× form (two absent
    // digits). Both branches need the other repeat-count to be 0.
    (twos == 1 && threes == 0 && zeros == 1) || (threes == 1 && twos == 0 && zeros == 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_accepts_known_pans() {
        assert!(luhn_check(b"4242424242424242"));
        assert!(luhn_check(b"79927398713"));
    }

    #[test]
    fn luhn_rejects_empty_and_garbage() {
        assert!(!luhn_check(b""));
        assert!(!luhn_check(b"not digits"));
        assert!(!luhn_check(b"79927398710"));
    }

    #[test]
    fn mod97_accepts_known_ibans() {
        // Wikipedia reference IBANs.
        assert!(mod97_check(b"GB82WEST12345698765432"));
        assert!(mod97_check(b"DE89370400440532013000"));
        assert!(mod97_check(b"CH9300762011623852957"));
        assert!(mod97_check(b"SA0380000000608010167519"));
    }

    #[test]
    fn mod97_rejects_corrupted_iban() {
        assert!(!mod97_check(b"GB82WEST12345698765431"));
        assert!(!mod97_check(b"DE00370400440532013000"));
    }

    #[test]
    fn verhoeff_accepts_known_aadhaar() {
        // Public Verhoeff fixtures.
        assert!(verhoeff_check(b"2363"));
        assert!(verhoeff_check(b"758722"));
        assert!(verhoeff_check(b"234123412346"));
    }

    #[test]
    fn verhoeff_rejects_corrupted() {
        assert!(!verhoeff_check(b"234123412345"));
        assert!(!verhoeff_check(b"000000000001"));
    }

    #[test]
    fn mod11_check_zero_weighted_sum_passes() {
        assert!(mod11_check(b"00000", &[1, 2, 3, 4, 5]));
        assert!(!mod11_check(b"12345", &[1, 1, 1, 1, 1]));
    }

    #[test]
    fn weighted_checksum_smoke() {
        let r = weighted_checksum(b"123", &[1, 1, 1], 10).unwrap();
        assert_eq!(r, 6);
        assert!(weighted_checksum(b"abc", &[1, 1, 1], 10).is_none());
        assert!(weighted_checksum(b"123", &[1, 1, 1], 0).is_none());
    }

    #[test]
    fn ean13_accepts_known_barcode() {
        // The Swiss AHV "756.9217.0769.85" without dots is "7569217076985"
        // — a published EAN-13 in https://en.wikipedia.org/wiki/AHV-Nummer.
        assert!(ean13_check(b"7569217076985"));
    }

    #[test]
    fn ean13_rejects_corrupted() {
        assert!(!ean13_check(b"7569217076984"));
        assert!(!ean13_check(b"123"));
    }

    #[test]
    fn iso7064_mod11_10_known_steuer_id() {
        // Published German Steuer-IdNr fixture from §139b AO commentary.
        assert!(iso7064_mod11_10(b"86095742719"));
    }

    #[test]
    fn iso7064_mod11_10_rejects_off_by_one() {
        assert!(!iso7064_mod11_10(b"86095742718"));
        assert!(!iso7064_mod11_10(b"8609574271")); // wrong length
    }

    #[test]
    fn de_steuer_id_structure_known_id_passes() {
        assert!(de_steuer_id_structure(b"86095742719"));
    }

    #[test]
    fn de_steuer_id_structure_rejects_all_unique() {
        // 0123456789X — every digit unique → no repeat, no missing → reject.
        assert!(!de_steuer_id_structure(b"01234567890"));
    }

    #[test]
    fn de_steuer_id_structure_accepts_post_2016_three_occurrence_form() {
        // Counts: '1' appears 3 times, '0' and '9' are absent, every
        // other digit appears once. Required after BZSt's 2016 reform.
        assert!(de_steuer_id_structure(b"11123456780"));
    }

    #[test]
    fn de_steuer_id_structure_rejects_quadruple_repeat() {
        // '1' appears 4 times — overflow guard must reject this
        // regardless of how many digits are absent.
        assert!(!de_steuer_id_structure(b"11112345670"));
    }

    #[test]
    fn de_steuer_id_structure_rejects_two_repeating_digits() {
        // '1' twice AND '2' twice → two separate repeats, no single
        // missing-digit branch matches.
        assert!(!de_steuer_id_structure(b"11223456780"));
    }

    #[test]
    fn leap_year_classification_matches_gregorian_rule() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn days_in_month_per_month_lookup() {
        assert_eq!(days_in_month(2024, 1), 31);
        assert_eq!(days_in_month(2024, 2), 29); // leap
        assert_eq!(days_in_month(2023, 2), 28); // non-leap
        assert_eq!(days_in_month(1900, 2), 28); // century non-leap
        assert_eq!(days_in_month(2024, 4), 30);
        assert_eq!(days_in_month(2024, 13), 0);
    }

    #[test]
    fn valid_dob_rejects_overflow_days() {
        assert!(valid_dob(2024, 2, 29));
        assert!(!valid_dob(2023, 2, 29));
        assert!(!valid_dob(1991, 2, 30));
        assert!(!valid_dob(2024, 4, 31));
        assert!(!valid_dob(2024, 0, 1));
        assert!(!valid_dob(2024, 13, 1));
        assert!(!valid_dob(2024, 1, 0));
    }
}
