//! Glob-based allow-list for script canonical names.
//!
//! Canonical names look like `sn360.diagnostics.tcp_ping`. The
//! control plane is the single authority for canonical names; the
//! agent only decides whether a name matches at least one of the
//! glob patterns the operator pinned in
//! `modules.script_runner.allowlist`.
//!
//! Patterns support two wildcards:
//!
//! - `*` matches any sequence of characters within a segment, where
//!   a segment is delimited by `.` (e.g. `sn360.*.tcp_ping` matches
//!   `sn360.diagnostics.tcp_ping` but NOT
//!   `sn360.diagnostics.deep.tcp_ping`).
//! - `**` matches any sequence of characters including `.` (e.g.
//!   `sn360.**` matches `sn360.diagnostics.tcp_ping` and any deeper
//!   path).
//!
//! The matcher is intentionally minimal — we don't pull in the
//! `glob` crate because we only need two wildcards and never want
//! the matcher to walk the filesystem.

/// Compiled allow-list.
///
/// `Allowlist` is `deny-by-default`: an empty patterns list rejects
/// every canonical name. Construct from a `Vec<String>` of glob
/// patterns and call [`Allowlist::is_allowed`] per script.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    patterns: Vec<String>,
}

impl Allowlist {
    /// Build a new allow-list from raw glob patterns. Patterns are
    /// stored verbatim; the matching cost is paid at lookup time.
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    /// Returns `true` when `canonical_name` matches at least one of
    /// the configured patterns. Returns `false` for an empty
    /// allow-list (deny-by-default).
    pub fn is_allowed(&self, canonical_name: &str) -> bool {
        self.patterns
            .iter()
            .any(|pat| matches_pattern(pat, canonical_name))
    }

    /// Number of patterns in the allow-list. Useful for diagnostics
    /// and tests.
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` when no patterns were configured.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// Match `pattern` against `name` using `*` (segment wildcard) and
/// `**` (multi-segment wildcard).
fn matches_pattern(pattern: &str, name: &str) -> bool {
    matches_recursive(pattern.as_bytes(), name.as_bytes())
}

fn matches_recursive(pattern: &[u8], name: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }

    // `**` consumes any number of characters including `.`.
    if pattern.starts_with(b"**") {
        let rest = &pattern[2..];
        if rest.is_empty() {
            return true;
        }
        // Try every suffix of `name` against the remaining pattern.
        for i in 0..=name.len() {
            if matches_recursive(rest, &name[i..]) {
                return true;
            }
        }
        return false;
    }

    // `*` consumes any non-`.` characters within a single segment.
    if pattern[0] == b'*' {
        let rest = &pattern[1..];
        if rest.is_empty() {
            // Trailing single `*` matches the rest of the segment.
            return !name.contains(&b'.');
        }
        for i in 0..=name.len() {
            // Stop at segment boundary.
            if i > 0 && name[i - 1] == b'.' {
                break;
            }
            if matches_recursive(rest, &name[i..]) {
                return true;
            }
        }
        return false;
    }

    // Literal byte.
    if name.is_empty() || pattern[0] != name[0] {
        return false;
    }
    matches_recursive(&pattern[1..], &name[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_denies_everything() {
        let al = Allowlist::default();
        assert!(!al.is_allowed("sn360.diagnostics.tcp_ping"));
        assert!(!al.is_allowed(""));
    }

    #[test]
    fn literal_match_is_strict() {
        let al = Allowlist::new(vec!["sn360.diagnostics.tcp_ping".to_string()]);
        assert!(al.is_allowed("sn360.diagnostics.tcp_ping"));
        assert!(!al.is_allowed("sn360.diagnostics.tcp_ping.extra"));
        assert!(!al.is_allowed("sn360.diagnostics.tcp"));
    }

    #[test]
    fn segment_wildcard_does_not_cross_dots() {
        let al = Allowlist::new(vec!["sn360.diagnostics.*".to_string()]);
        assert!(al.is_allowed("sn360.diagnostics.tcp_ping"));
        assert!(al.is_allowed("sn360.diagnostics.dns_lookup"));
        // Does not cross a dot — depth 4 must not match a depth-3
        // pattern.
        assert!(!al.is_allowed("sn360.diagnostics.deep.tcp_ping"));
        // Other prefixes are rejected.
        assert!(!al.is_allowed("attacker.diagnostics.tcp_ping"));
    }

    #[test]
    fn double_star_crosses_dots() {
        let al = Allowlist::new(vec!["sn360.**".to_string()]);
        assert!(al.is_allowed("sn360.diagnostics.tcp_ping"));
        assert!(al.is_allowed("sn360.diagnostics.deep.tcp_ping"));
        assert!(al.is_allowed("sn360.x"));
        assert!(!al.is_allowed("attacker.diagnostics.tcp_ping"));
    }

    #[test]
    fn middle_segment_wildcard() {
        let al = Allowlist::new(vec!["sn360.*.tcp_ping".to_string()]);
        assert!(al.is_allowed("sn360.diagnostics.tcp_ping"));
        assert!(al.is_allowed("sn360.support.tcp_ping"));
        // Segment wildcard does not cross dots.
        assert!(!al.is_allowed("sn360.diagnostics.deep.tcp_ping"));
    }

    #[test]
    fn multiple_patterns_are_logical_or() {
        let al = Allowlist::new(vec![
            "sn360.diagnostics.*".to_string(),
            "sn360.support.run".to_string(),
        ]);
        assert!(al.is_allowed("sn360.diagnostics.tcp_ping"));
        assert!(al.is_allowed("sn360.support.run"));
        assert!(!al.is_allowed("sn360.support.other"));
    }

    #[test]
    fn len_and_is_empty_helpers() {
        let empty = Allowlist::default();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let two = Allowlist::new(vec!["a".to_string(), "b".to_string()]);
        assert!(!two.is_empty());
        assert_eq!(two.len(), 2);
    }
}
