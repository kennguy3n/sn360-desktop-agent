//! Rule bundle loader.
//!
//! Rule bundles are packed as [MessagePack](https://msgpack.org/) on
//! disk for compact storage and fast parsing.  Each bundle carries a
//! monotonic version number — consumers can diff by version and pull
//! only the delta from the Tenant Rule Distribution Service (TRDS).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Severity classification used across IOC and behavioural rules.
pub const SEV_INFO: &str = "info";
pub const SEV_LOW: &str = "low";
pub const SEV_MEDIUM: &str = "medium";
pub const SEV_HIGH: &str = "high";
pub const SEV_CRITICAL: &str = "critical";

/// A single string-valued IOC (domain, URL, file path, hostname, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringIoc {
    /// Unique rule identifier.
    pub id: String,
    /// The string to look for in event fields (case-sensitive).
    pub value: String,
    /// What kind of artifact this is: "domain", "url", "path", "cmdline", …
    pub kind: String,
    /// Severity — one of [`SEV_INFO`]..[`SEV_CRITICAL`].
    pub severity: String,
    /// Human-readable description.
    pub description: String,
}

/// A hash-based IOC — SHA-256 is the expected format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashIoc {
    pub id: String,
    /// Lower-case hex SHA-256.
    pub sha256: String,
    pub severity: String,
    pub description: String,
}

/// An IP-based IOC — textual IPv4/IPv6 representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIoc {
    pub id: String,
    pub ip: String,
    pub severity: String,
    pub description: String,
}

/// Collection of IOCs in a bundle, split by matcher backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IocList {
    /// IOCs matched via Aho-Corasick against stringly-typed event fields.
    #[serde(default)]
    pub strings: Vec<StringIoc>,
    /// IOCs matched via a bloom filter against file hashes.
    #[serde(default)]
    pub hashes: Vec<HashIoc>,
    /// IOCs matched via a bloom filter against IP addresses.
    #[serde(default)]
    pub ips: Vec<IpIoc>,
}

/// A behavioural rule expressed in the LDE's JSON DSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralRule {
    pub id: String,
    pub severity: String,
    pub description: String,
    /// Which event source this rule listens on: "fim" or "logcollector".
    pub event_source: String,
    /// The matcher variant.
    pub kind: BehavioralRuleKind,
}

/// Behavioural rule matcher variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BehavioralRuleKind {
    /// Fire when a keyed entity exceeds `min_count` occurrences in
    /// `window_secs`.
    Threshold {
        /// Substring that must appear in the event's matched string
        /// fields for the occurrence to count.
        contains: String,
        /// Minimum occurrences inside the sliding window.
        min_count: u32,
        /// Window size in seconds.
        window_secs: u64,
    },
    /// Fire when an ordered sequence of substrings all appear in a
    /// single entity's event stream within `window_secs`.
    Sequence {
        /// Ordered list of substrings to match.
        sequence: Vec<String>,
        /// Window size in seconds.
        window_secs: u64,
    },
}

/// A complete on-disk rule bundle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleBundle {
    /// Monotonic bundle version.  Consumers compare versions to decide
    /// whether to re-pull from TRDS.
    #[serde(default)]
    pub version: u64,
    /// ISO-8601 generation timestamp.
    #[serde(default)]
    pub generated_at: String,
    /// IOCs grouped by backend.
    #[serde(default)]
    pub iocs: IocList,
    /// Behavioural rules evaluated by the state machine.
    #[serde(default)]
    pub behavioral: Vec<BehavioralRule>,
    /// Absolute paths to `.yar`/`.yara` rule files loaded by the YARA
    /// scanner.
    #[serde(default)]
    pub yara_paths: Vec<PathBuf>,
}

impl RuleBundle {
    /// Load a MessagePack-encoded bundle from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read rule bundle {}: {}", path.display(), e))?;
        Self::from_msgpack(&bytes)
    }

    /// Decode a MessagePack byte slice into a [`RuleBundle`].
    pub fn from_msgpack(bytes: &[u8]) -> anyhow::Result<Self> {
        rmp_serde::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("failed to decode rule bundle: {}", e))
    }

    /// Serialise to MessagePack (primarily for tests / tooling).
    pub fn to_msgpack(&self) -> anyhow::Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| anyhow::anyhow!("failed to encode rule bundle: {}", e))
    }

    /// Write this bundle to `path` in MessagePack form.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let bytes = self.to_msgpack()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, bytes)
            .map_err(|e| anyhow::anyhow!("failed to write bundle {}: {}", path.display(), e))
    }

    /// Returns whether `self` is strictly newer than `other`.
    pub fn is_newer_than(&self, other: &RuleBundle) -> bool {
        self.version > other.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuleBundle {
        RuleBundle {
            version: 7,
            generated_at: "2026-04-20T00:00:00Z".to_string(),
            iocs: IocList {
                strings: vec![StringIoc {
                    id: "ioc-1".into(),
                    value: "evil.example.com".into(),
                    kind: "domain".into(),
                    severity: SEV_HIGH.into(),
                    description: "known C2".into(),
                }],
                hashes: vec![HashIoc {
                    id: "hash-1".into(),
                    sha256: "a".repeat(64),
                    severity: SEV_CRITICAL.into(),
                    description: "malware".into(),
                }],
                ips: vec![IpIoc {
                    id: "ip-1".into(),
                    ip: "203.0.113.9".into(),
                    severity: SEV_MEDIUM.into(),
                    description: "blocklist".into(),
                }],
            },
            behavioral: vec![BehavioralRule {
                id: "behav-1".into(),
                severity: SEV_MEDIUM.into(),
                description: "brute force ssh".into(),
                event_source: "logcollector".into(),
                kind: BehavioralRuleKind::Threshold {
                    contains: "authentication failure".into(),
                    min_count: 5,
                    window_secs: 60,
                },
            }],
            yara_paths: vec![PathBuf::from("/etc/yara/example.yar")],
        }
    }

    #[test]
    fn test_msgpack_roundtrip() {
        let bundle = sample();
        let bytes = bundle.to_msgpack().unwrap();
        let decoded = RuleBundle::from_msgpack(&bytes).unwrap();
        assert_eq!(decoded.version, 7);
        assert_eq!(decoded.iocs.strings.len(), 1);
        assert_eq!(decoded.iocs.hashes.len(), 1);
        assert_eq!(decoded.iocs.ips.len(), 1);
        assert_eq!(decoded.behavioral.len(), 1);
        assert_eq!(decoded.yara_paths.len(), 1);
    }

    #[test]
    fn test_load_and_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.msgpack");
        let bundle = sample();
        bundle.save(&path).unwrap();
        let loaded = RuleBundle::load(&path).unwrap();
        assert_eq!(loaded.version, bundle.version);
    }

    #[test]
    fn test_load_missing_file_errors() {
        let err = RuleBundle::load(Path::new("/nonexistent/does-not-exist")).unwrap_err();
        assert!(format!("{err}").contains("failed to read"));
    }

    #[test]
    fn test_is_newer_than() {
        let a = RuleBundle {
            version: 2,
            ..Default::default()
        };
        let b = RuleBundle {
            version: 1,
            ..Default::default()
        };
        assert!(a.is_newer_than(&b));
        assert!(!b.is_newer_than(&a));
        assert!(!a.is_newer_than(&a));
    }

    #[test]
    fn test_default_is_empty() {
        let b = RuleBundle::default();
        assert_eq!(b.version, 0);
        assert!(b.iocs.strings.is_empty());
        assert!(b.behavioral.is_empty());
        assert!(b.yara_paths.is_empty());
    }
}
