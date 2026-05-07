//! Update check: fetch a signed manifest and determine whether the
//! advertised version supersedes the currently running build.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

use sda_core::config::UpdateConfig;

/// Signed manifest served by the update endpoint.
///
/// Wire format (JSON):
/// ```json
/// {
///   "version": "0.2.0",
///   "url": "https://updates.example.com/sda/sda-agent-0.2.0",
///   "sha256": "c0ffee…",
///   "signature": "hex-encoded Ed25519 signature over sha256 bytes"
/// }
/// ```
///
/// `sha256` is a lowercase hex digest of the binary. `signature` is an
/// Ed25519 signature over the raw 32-byte digest (not the ASCII hex)
/// encoded as hex for JSON transport.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
}

/// Fetch the update manifest and decide whether an update is available.
///
/// Returns `Ok(None)` when the server advertises a version that is
/// older than or equal to `current_version`. Returns `Ok(Some(..))`
/// when an upgrade is indicated, and `Err` if the fetch or parse fails.
pub async fn check_for_update(
    cfg: &UpdateConfig,
    current_version: &str,
) -> Result<Option<UpdateManifest>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        // Small, polite UA so operators can distinguish agent traffic
        // from ad-hoc curl pokes in their server logs.
        .user_agent(concat!("sda-agent-updater/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build reqwest client")?;

    let resp = client
        .get(&cfg.server_url)
        .send()
        .await
        .with_context(|| format!("failed to GET {}", cfg.server_url))?;

    if !resp.status().is_success() {
        return Err(anyhow!("update server returned status {}", resp.status()));
    }

    let manifest: UpdateManifest = resp
        .json()
        .await
        .context("failed to decode update manifest")?;

    if is_newer(&manifest.version, current_version) {
        Ok(Some(manifest))
    } else {
        Ok(None)
    }
}

/// Compare two dotted version strings (e.g. `"0.2.0"` > `"0.1.9"`).
///
/// Splits on `.`, parses each segment as a `u64`, and compares
/// lexicographically. Missing trailing segments are treated as zero,
/// so `"0.2" == "0.2.0"` and `"0.2.1" > "0.2"`. Non-numeric segments
/// compare as 0 which gives a sensible answer for release tags like
/// `"0.2.0-rc1"` (they evaluate equal to the final release) without
/// pulling in a full semver parser.
///
/// Both parsed vectors are padded with trailing zeros to the same
/// length before comparison so that `"0.2"` and `"0.2.0"` are treated
/// as equal rather than `"0.2.0"` being considered strictly newer
/// just because it has an extra explicit `0` segment.
pub(crate) fn is_newer(candidate: &str, current: &str) -> bool {
    let mut a = parse_version(candidate);
    let mut b = parse_version(current);
    let len = a.len().max(b.len());
    a.resize(len, 0);
    b.resize(len, 0);
    a > b
}

fn parse_version(s: &str) -> Vec<u64> {
    s.split('.')
        .map(|seg| {
            // Strip anything after a non-digit so `0.2.0-rc1` parses
            // as `[0, 2, 0]`.
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_patch_wins() {
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.9", "0.1.10"));
    }

    #[test]
    fn equal_versions_are_not_newer() {
        assert!(!is_newer("0.2.0", "0.2.0"));
    }

    #[test]
    fn newer_minor_wins_over_older_patch() {
        assert!(is_newer("0.2.0", "0.1.99"));
    }

    #[test]
    fn missing_trailing_segments_default_to_zero() {
        assert!(is_newer("0.2", "0.1.99"));
        assert!(!is_newer("0.2", "0.2.0"));
    }

    /// Regression test for the trailing-zero comparison bug (A2).
    ///
    /// `"0.2.0"` and `"0.2"` must compare equal, and `"0.2.1"` must
    /// be strictly newer than `"0.2"` — otherwise an operator running
    /// the advertised `"0.2.0"` against a manifest that reports
    /// `"0.2"` would flap into a re-download loop every tick.
    #[test]
    fn trailing_zero_segments_compare_equal() {
        assert!(!is_newer("0.2.0", "0.2"));
        assert!(!is_newer("0.2", "0.2.0"));
        assert!(is_newer("0.2.1", "0.2"));
        assert!(!is_newer("0.2", "0.2.1"));
    }

    #[test]
    fn prerelease_suffix_is_ignored() {
        // `-rc1` is dropped; both versions parse as [0, 2, 0].
        assert!(!is_newer("0.2.0-rc1", "0.2.0"));
        assert!(is_newer("0.2.1-rc1", "0.2.0"));
    }

    #[test]
    fn manifest_deserializes_from_expected_json() {
        let json = r#"{
            "version": "0.2.0",
            "url": "https://updates.example.com/sda/sda-agent-0.2.0",
            "sha256": "deadbeef",
            "signature": "ab12"
        }"#;
        let m: UpdateManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.version, "0.2.0");
        assert_eq!(m.url, "https://updates.example.com/sda/sda-agent-0.2.0");
        assert_eq!(m.sha256, "deadbeef");
        assert_eq!(m.signature, "ab12");
    }
}
