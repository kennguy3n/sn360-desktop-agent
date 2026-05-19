//! Test-only AMSI mock used by the AMSI integration tests.
//!
//! Real AMSI integration requires Windows + SYSTEM, neither of which
//! is available in CI. The mock simulates the surface area that
//! `crate::amsi` (compiled only on Windows + `--features amsi`)
//! exposes: a provider that consumes byte slices and yields a list
//! of synthetic [`MemoryMatch`]es.
//!
//! Tests in `crate::tests` that need to exercise the AMSI hot path
//! drive a `MockAmsiProvider` end-to-end through
//! [`crate::MemoryMatcher`] so the same code path that consumes YARA
//! hits also consumes AMSI hits.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use crate::{MemoryAlertKind, MemoryMatch, MemoryMatcher};
use sda_pal::memory_scanner::MemoryRegion;

/// A canned AMSI submission outcome.
#[derive(Debug, Clone)]
pub struct CannedAmsiResult {
    /// Pattern (substring) that must appear in the submitted bytes
    /// before this canned result fires. Use an empty string to fire
    /// on every submission.
    pub trigger: Vec<u8>,
    /// Human-readable description that lands in [`MemoryMatch::description`].
    pub description: String,
}

/// Test-only AMSI provider that records each submission and, on a
/// trigger match, yields a [`MemoryMatch`] tagged with
/// [`MemoryAlertKind::AmsiMatch`].
pub struct MockAmsiProvider {
    canned: Mutex<Vec<CannedAmsiResult>>,
    submissions: AtomicU32,
}

impl MockAmsiProvider {
    /// Build a provider that yields one `MemoryMatch` per entry in
    /// `canned` whose `trigger` is a substring of the submitted
    /// bytes. Pass an empty `Vec` for a no-hit mock.
    pub fn new(canned: Vec<CannedAmsiResult>) -> Self {
        Self {
            canned: Mutex::new(canned),
            submissions: AtomicU32::new(0),
        }
    }

    /// Number of times [`MemoryMatcher::match_bytes`] was invoked.
    pub fn submissions(&self) -> u32 {
        self.submissions.load(Ordering::Relaxed)
    }
}

impl MemoryMatcher for MockAmsiProvider {
    fn match_bytes(&self, _pid: u32, _region: &MemoryRegion, bytes: &[u8]) -> Vec<MemoryMatch> {
        self.submissions.fetch_add(1, Ordering::Relaxed);
        let canned = self.canned.lock().expect("amsi mock lock poisoned");
        canned
            .iter()
            .filter(|c| c.trigger.is_empty() || contains_subslice(bytes, &c.trigger))
            .map(|c| MemoryMatch {
                alert_type: MemoryAlertKind::AmsiMatch,
                description: c.description.clone(),
            })
            .collect()
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_pal::memory_scanner::{MappingKind, MemoryPermissions, MemoryRegion};

    fn region() -> MemoryRegion {
        MemoryRegion {
            base: 0x1000,
            size: 4096,
            permissions: MemoryPermissions {
                readable: true,
                writable: true,
                executable: true,
            },
            mapping: MappingKind::Anonymous,
        }
    }

    #[test]
    fn empty_canned_yields_no_hits() {
        let p = MockAmsiProvider::new(vec![]);
        assert!(p.match_bytes(99, &region(), b"anything").is_empty());
        assert_eq!(p.submissions(), 1);
    }

    #[test]
    fn matching_trigger_yields_amsi_match() {
        let p = MockAmsiProvider::new(vec![CannedAmsiResult {
            trigger: b"powershell -enc".to_vec(),
            description: "encoded PowerShell".into(),
        }]);
        let hits = p.match_bytes(99, &region(), b"$x = powershell -enc abcdef");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].alert_type, MemoryAlertKind::AmsiMatch);
        assert_eq!(hits[0].description, "encoded PowerShell");
    }

    #[test]
    fn non_matching_trigger_yields_nothing() {
        let p = MockAmsiProvider::new(vec![CannedAmsiResult {
            trigger: b"mimikatz".to_vec(),
            description: "credential dumper".into(),
        }]);
        assert!(p.match_bytes(99, &region(), b"clean content").is_empty());
    }

    #[test]
    fn empty_trigger_fires_on_every_submission() {
        let p = MockAmsiProvider::new(vec![CannedAmsiResult {
            trigger: vec![],
            description: "fire on every submission".into(),
        }]);
        assert_eq!(p.match_bytes(99, &region(), b"").len(), 1);
        assert_eq!(p.match_bytes(99, &region(), b"anything").len(), 1);
        assert_eq!(p.submissions(), 2);
    }
}
