//! IOC matching engine.
//!
//! * String IOCs (domains, URLs, paths) are matched with an
//!   Aho-Corasick automaton — O(n + matches) across all patterns in a
//!   single pass.
//! * Hash IOCs (SHA-256) and IP IOCs are probed through a
//!   [`Bloom`](bloomfilter::Bloom) filter sized for the desired false
//!   positive rate, with an authoritative `HashSet` fallback so reports
//!   are never wrong.

use std::collections::{HashMap, HashSet};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use bloomfilter::Bloom;

use crate::rule_store::{HashIoc, IocList, IpIoc, StringIoc};

/// A single IOC match produced by [`IocMatcher::matches`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocMatch {
    /// Rule identifier from the bundle.
    pub rule_id: String,
    /// "string", "hash" or "ip".
    pub rule_type: &'static str,
    /// Severity of the matched rule.
    pub severity: String,
    /// Human-readable description.
    pub description: String,
    /// The exact value that triggered the match.
    pub matched_value: String,
}

/// Compiled IOC matcher.
///
/// Construction is O(total-IOC-length) for the Aho-Corasick build and
/// O(N) for bloom/hashset population.  Matching is O(n) in the length
/// of the searched event field plus O(1) per hash/IP lookup.
pub struct IocMatcher {
    ac: Option<AhoCorasick>,
    string_rules: Vec<StringIoc>,
    hash_bloom: Option<Bloom<String>>,
    hash_set: HashSet<String>,
    hash_rules: HashMap<String, HashIoc>,
    ip_bloom: Option<Bloom<String>>,
    ip_set: HashSet<String>,
    ip_rules: HashMap<String, IpIoc>,
}

impl IocMatcher {
    /// Build a matcher from a rule bundle's IOC list.
    ///
    /// `bloom_fpr` is the target false-positive rate for the
    /// hash/IP filters.  When either set is empty the corresponding
    /// bloom is elided.
    pub fn build(iocs: &IocList, bloom_fpr: f64) -> anyhow::Result<Self> {
        // --- Aho-Corasick for string IOCs ---
        let (ac, string_rules) = if iocs.strings.is_empty() {
            (None, Vec::new())
        } else {
            let patterns: Vec<&str> = iocs.strings.iter().map(|i| i.value.as_str()).collect();
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)
                .map_err(|e| anyhow::anyhow!("Aho-Corasick build failed: {}", e))?;
            (Some(ac), iocs.strings.clone())
        };

        // --- Hash bloom + authoritative set ---
        let hash_set: HashSet<String> = iocs
            .hashes
            .iter()
            .map(|h| h.sha256.to_ascii_lowercase())
            .collect();
        let hash_bloom = build_bloom(&hash_set, bloom_fpr);
        let hash_rules: HashMap<String, HashIoc> = iocs
            .hashes
            .iter()
            .map(|h| (h.sha256.to_ascii_lowercase(), h.clone()))
            .collect();

        // --- IP bloom + authoritative set ---
        let ip_set: HashSet<String> = iocs.ips.iter().map(|i| i.ip.to_string()).collect();
        let ip_bloom = build_bloom(&ip_set, bloom_fpr);
        let ip_rules: HashMap<String, IpIoc> = iocs
            .ips
            .iter()
            .map(|i| (i.ip.to_string(), i.clone()))
            .collect();

        Ok(Self {
            ac,
            string_rules,
            hash_bloom,
            hash_set,
            hash_rules,
            ip_bloom,
            ip_set,
            ip_rules,
        })
    }

    /// Match the provided event fields against all string IOCs.
    pub fn match_strings(&self, fields: &[&str]) -> Vec<IocMatch> {
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for field in fields {
            for m in ac.find_iter(field) {
                if let Some(rule) = self.string_rules.get(m.pattern().as_usize()) {
                    out.push(IocMatch {
                        rule_id: rule.id.clone(),
                        rule_type: "string",
                        severity: rule.severity.clone(),
                        description: rule.description.clone(),
                        matched_value: rule.value.clone(),
                    });
                }
            }
        }
        out
    }

    /// Check a single SHA-256 hex digest against the hash IOC set.
    pub fn match_hash(&self, sha256_hex: &str) -> Option<IocMatch> {
        let key = sha256_hex.to_ascii_lowercase();
        if let Some(bloom) = &self.hash_bloom {
            if !bloom.check(&key) {
                return None;
            }
        } else if self.hash_set.is_empty() {
            return None;
        }
        if !self.hash_set.contains(&key) {
            // Bloom filter false positive.
            return None;
        }
        self.hash_rules.get(&key).map(|r| IocMatch {
            rule_id: r.id.clone(),
            rule_type: "hash",
            severity: r.severity.clone(),
            description: r.description.clone(),
            matched_value: r.sha256.clone(),
        })
    }

    /// Check a single textual IP against the IP IOC set.
    pub fn match_ip(&self, ip: &str) -> Option<IocMatch> {
        if let Some(bloom) = &self.ip_bloom {
            if !bloom.check(&ip.to_string()) {
                return None;
            }
        } else if self.ip_set.is_empty() {
            return None;
        }
        if !self.ip_set.contains(ip) {
            return None;
        }
        self.ip_rules.get(ip).map(|r| IocMatch {
            rule_id: r.id.clone(),
            rule_type: "ip",
            severity: r.severity.clone(),
            description: r.description.clone(),
            matched_value: r.ip.clone(),
        })
    }

    /// Composite match against event fields, hash and IP values.
    ///
    /// All three backends are probed; callers receive a flat list of
    /// matches in deterministic order (strings, then hash, then IP).
    pub fn matches(
        &self,
        fields: &[&str],
        sha256_hex: Option<&str>,
        ip: Option<&str>,
    ) -> Vec<IocMatch> {
        let mut out = self.match_strings(fields);
        if let Some(h) = sha256_hex {
            if let Some(m) = self.match_hash(h) {
                out.push(m);
            }
        }
        if let Some(addr) = ip {
            if let Some(m) = self.match_ip(addr) {
                out.push(m);
            }
        }
        out
    }

    /// Total number of rules loaded across all backends.
    pub fn rule_count(&self) -> usize {
        self.string_rules.len() + self.hash_rules.len() + self.ip_rules.len()
    }
}

fn build_bloom(set: &HashSet<String>, fpr: f64) -> Option<Bloom<String>> {
    if set.is_empty() {
        return None;
    }
    let fpr = fpr.clamp(1e-6, 0.5);
    let mut bloom = Bloom::<String>::new_for_fp_rate(set.len().max(1), fpr);
    for v in set {
        bloom.set(v);
    }
    Some(bloom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_store::{SEV_HIGH, SEV_MEDIUM};

    fn mk_iocs() -> IocList {
        IocList {
            strings: vec![
                StringIoc {
                    id: "s-evil-com".into(),
                    value: "evil.example.com".into(),
                    kind: "domain".into(),
                    severity: SEV_HIGH.into(),
                    description: "".into(),
                },
                StringIoc {
                    id: "s-path".into(),
                    value: "/tmp/suspicious.exe".into(),
                    kind: "path".into(),
                    severity: SEV_MEDIUM.into(),
                    description: "".into(),
                },
            ],
            hashes: vec![HashIoc {
                id: "h-1".into(),
                sha256: "a".repeat(64),
                severity: SEV_HIGH.into(),
                description: "".into(),
            }],
            ips: vec![IpIoc {
                id: "i-1".into(),
                ip: "203.0.113.9".into(),
                severity: SEV_MEDIUM.into(),
                description: "".into(),
            }],
        }
    }

    #[test]
    fn test_aho_corasick_matches_string_fields() {
        let m = IocMatcher::build(&mk_iocs(), 0.01).unwrap();
        let hits = m.match_strings(&["connection to evil.example.com happened"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "s-evil-com");
        assert_eq!(hits[0].rule_type, "string");
    }

    #[test]
    fn test_aho_corasick_matches_multiple_iocs() {
        let m = IocMatcher::build(&mk_iocs(), 0.01).unwrap();
        let hits = m.match_strings(&[
            "evil.example.com",
            "dropped /tmp/suspicious.exe",
            "benign payload",
        ]);
        assert_eq!(hits.len(), 2);
        let ids: Vec<_> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"s-evil-com"));
        assert!(ids.contains(&"s-path"));
    }

    #[test]
    fn test_string_match_misses_cleanly() {
        let m = IocMatcher::build(&mk_iocs(), 0.01).unwrap();
        assert!(m.match_strings(&["nothing interesting here"]).is_empty());
    }

    #[test]
    fn test_hash_bloom_reports_true_positive() {
        let m = IocMatcher::build(&mk_iocs(), 0.001).unwrap();
        let hit = m.match_hash(&"A".repeat(64)).expect("expected hash hit");
        assert_eq!(hit.rule_type, "hash");
        assert_eq!(hit.rule_id, "h-1");
    }

    #[test]
    fn test_hash_bloom_rejects_unknown() {
        let m = IocMatcher::build(&mk_iocs(), 0.001).unwrap();
        // A hash that is definitely not in the set; bloom will almost
        // certainly reject, and the authoritative set check rejects
        // any surviving false positive.
        assert!(m.match_hash(&"b".repeat(64)).is_none());
    }

    #[test]
    fn test_ip_bloom_true_and_false_paths() {
        let m = IocMatcher::build(&mk_iocs(), 0.001).unwrap();
        assert!(m.match_ip("203.0.113.9").is_some());
        assert!(m.match_ip("198.51.100.4").is_none());
    }

    #[test]
    fn test_empty_bundle_matches_nothing() {
        let iocs = IocList::default();
        let m = IocMatcher::build(&iocs, 0.01).unwrap();
        assert_eq!(m.rule_count(), 0);
        assert!(m
            .matches(&["anything"], Some(&"a".repeat(64)), Some("1.2.3.4"))
            .is_empty());
    }

    #[test]
    fn test_rule_count_sums_backends() {
        let m = IocMatcher::build(&mk_iocs(), 0.01).unwrap();
        assert_eq!(m.rule_count(), 4);
    }
}
