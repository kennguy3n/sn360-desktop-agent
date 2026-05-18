//! RFC 8785 canonical JSON serializer.
//!
//! Used as the signature pre-image for `SignedActionJob` and
//! `EvidenceRecord` per `docs/wire-protocols/device-control.md`
//! § 7.2 and § 9.2. The canonical form is what the control plane
//! signs and what the agent re-derives to verify.
//!
//! Algorithm summary (RFC 8785, simplified for our subset):
//!
//! - Object members are emitted in lexicographic order of their
//!   UTF-16 code-unit-encoded keys.
//! - No whitespace between tokens.
//! - String escapes follow JSON exactly: `\"`, `\\`, `\b`, `\f`,
//!   `\n`, `\r`, `\t`, and `\u00XX` for control characters.
//! - Numbers are encoded by `serde_json` already, which uses the
//!   shortest round-trippable form for floats and the decimal
//!   integer form for integers.
//! - `null`, `true`, `false` are emitted verbatim.
//!
//! We deliberately do NOT support arbitrary `f64` values: the wire
//! schemas in docs/wire-protocols/device-control.md only carry integers, strings, booleans,
//! arrays, objects, and `null`. Any `Number::Float` in a payload is
//! a producer bug — we surface it as an error rather than guessing
//! at a canonical float encoding (which RFC 8785 specifies but our
//! payloads must never exercise).

use serde_json::Value;

use thiserror::Error;

/// Errors returned by [`canonicalize`].
#[derive(Debug, Error)]
pub enum CanonicalizeError {
    /// A floating-point number was encountered. Device Control
    /// payloads must use integer or string encodings — see module
    /// docs.
    #[error("floats are not allowed in canonical Device Control payloads (got {0})")]
    FloatNotAllowed(f64),
    /// A non-finite number (NaN / ±Inf) was encountered.
    #[error("non-finite number {0:?} cannot be canonicalised")]
    NonFinite(serde_json::Number),
}

/// Produce the RFC 8785 canonical JSON encoding of `value`.
///
/// Returns the bytes that should be Ed25519-signed.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonicalizeError> {
    let mut out = Vec::with_capacity(256);
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalizeError> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785 § 3.2.3: object members are sorted by their
            // UTF-16 code-unit representation. For BMP-only ASCII
            // keys (which is what our schemas use) this collapses
            // to a plain byte-wise sort. We use UTF-16 sort to be
            // safe against accidental non-ASCII keys in `evidence`
            // / `args` blobs supplied by the control plane.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_compare(a, b));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                let value = map.get(*k).expect("key from map is present");
                write_value(value, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), CanonicalizeError> {
    if let Some(i) = n.as_i64() {
        out.extend_from_slice(itoa(i).as_bytes());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        out.extend_from_slice(utoa(u).as_bytes());
        return Ok(());
    }
    if let Some(f) = n.as_f64() {
        if !f.is_finite() {
            return Err(CanonicalizeError::NonFinite(n.clone()));
        }
        return Err(CanonicalizeError::FloatNotAllowed(f));
    }
    Err(CanonicalizeError::NonFinite(n.clone()))
}

fn itoa(v: i64) -> String {
    v.to_string()
}

fn utoa(v: u64) -> String {
    v.to_string()
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0c' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                let escape = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(escape.as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn utf16_compare(a: &str, b: &str) -> std::cmp::Ordering {
    let a_units: Vec<u16> = a.encode_utf16().collect();
    let b_units: Vec<u16> = b.encode_utf16().collect();
    a_units.cmp(&b_units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn c(v: &Value) -> String {
        let bytes = canonicalize(v).expect("canonicalize");
        String::from_utf8(bytes).expect("utf-8")
    }

    #[test]
    fn primitives() {
        assert_eq!(c(&Value::Null), "null");
        assert_eq!(c(&json!(true)), "true");
        assert_eq!(c(&json!(false)), "false");
        assert_eq!(c(&json!(0)), "0");
        assert_eq!(c(&json!(-1)), "-1");
        assert_eq!(c(&json!(42)), "42");
        assert_eq!(c(&json!(1u64 << 32)), "4294967296");
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(c(&json!("")), "\"\"");
        assert_eq!(c(&json!("hello")), "\"hello\"");
        assert_eq!(c(&json!("a\"b")), "\"a\\\"b\"");
        assert_eq!(c(&json!("a\\b")), "\"a\\\\b\"");
        assert_eq!(c(&json!("a\nb")), "\"a\\nb\"");
        assert_eq!(c(&json!("a\rb")), "\"a\\rb\"");
        assert_eq!(c(&json!("a\tb")), "\"a\\tb\"");
        // Backspace and form feed
        assert_eq!(c(&json!("\u{0008}")), "\"\\b\"");
        assert_eq!(c(&json!("\u{000c}")), "\"\\f\"");
    }

    #[test]
    fn ascii_control_chars_use_unicode_escape() {
        // \u0001 is below 0x20 and not a named escape
        assert_eq!(c(&json!("\u{0001}")), "\"\\u0001\"");
        assert_eq!(c(&json!("\u{001f}")), "\"\\u001f\"");
    }

    #[test]
    fn unicode_is_emitted_as_utf8() {
        // RFC 8785 emits Unicode literally in UTF-8 — only control
        // characters and the special escapes get \uXXXX.
        let bytes = canonicalize(&json!("héllo")).unwrap();
        // Expected: literal UTF-8 bytes for é
        assert_eq!(bytes, "\"héllo\"".as_bytes());
    }

    #[test]
    fn arrays_are_emitted_in_order() {
        assert_eq!(c(&json!([])), "[]");
        assert_eq!(c(&json!([1, 2, 3])), "[1,2,3]");
        assert_eq!(c(&json!([1, "two", null])), "[1,\"two\",null]");
    }

    #[test]
    fn object_keys_are_lexicographically_sorted() {
        let v = json!({
            "zeta": 1,
            "alpha": 2,
            "Mike": 3,
            "mike": 4,
        });
        // Capital letters sort before lowercase in UTF-16 (M = 77,
        // a = 97).
        assert_eq!(c(&v), "{\"Mike\":3,\"alpha\":2,\"mike\":4,\"zeta\":1}");
    }

    #[test]
    fn nested_objects_sort_at_each_level() {
        let v = json!({
            "outer": {
                "z": 1,
                "a": [
                    {"y": 1, "x": 2},
                    3
                ]
            },
            "id": "abc"
        });
        let s = c(&v);
        assert_eq!(
            s,
            "{\"id\":\"abc\",\"outer\":{\"a\":[{\"x\":2,\"y\":1},3],\"z\":1}}"
        );
    }

    #[test]
    fn output_is_deterministic_across_input_orderings() {
        // serde_json::Map preserves insertion order; we must produce
        // the same canonical output regardless of how the input was
        // constructed.
        let a: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(c(&a), c(&b));
    }

    #[test]
    fn floats_are_rejected() {
        let v = json!(1.5);
        let r = canonicalize(&v);
        assert!(matches!(r, Err(CanonicalizeError::FloatNotAllowed(_))));
    }

    #[test]
    fn signed_action_job_pre_image_blanks_signature_field() {
        // docs/wire-protocols/device-control.md § 7.2 rule: the canonical pre-image of a
        // signed-job is the canonical encoding with `signature`
        // replaced by an empty string. We don't replace here — the
        // caller does — but make sure the canonicalizer treats the
        // empty string and the array-of-bytes encoding differently
        // so the caller's substitution actually produces a stable
        // pre-image.
        let mut v = json!({
            "signature": [1, 2, 3],
            "key_id": "k",
        });
        // Caller substitution
        v["signature"] = Value::String(String::new());
        let s = c(&v);
        assert_eq!(s, "{\"key_id\":\"k\",\"signature\":\"\"}");
    }
}
