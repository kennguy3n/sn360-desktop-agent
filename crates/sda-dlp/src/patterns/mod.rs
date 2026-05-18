//! DLP pattern catalogue.
//!
//! The DLP scanner consumes a `Vec<PatternDef>` and feeds the regex
//! engine + per-pattern structural validator. The catalogue is split
//! into four region modules — Asia, GCC, Europe, and Global — that
//! each contribute a fixed list of [`PatternDef`]s. The full set is
//! the concatenation surfaced by [`baseline_patterns`].
//!
//! ## Selection
//!
//! Operators choose patterns via [`select`], which understands:
//!
//! - exact category IDs, e.g. `"pii.ssn"`;
//! - regional globs, e.g. `"asia.*"`, `"europe.*"`;
//! - category-prefix globs, e.g. `"pii.*"`, `"pci.*"`, `"secrets.*"`;
//! - the wildcard token `"*"` (selects every pattern).
//!
//! An empty selection equals "select everything", matching the
//! historic default. Unknown selectors are silently dropped so a
//! typo'd config can't take the module down — the caller (DLP
//! module) logs which selectors were dropped at warn level.
//!
//! ## Redaction
//!
//! Matched bytes never leave the scanner. The scanner emits only
//! `(category, offset, length, blake3_fingerprint)` to the event
//! bus. The validators below are pure functions over the matched
//! byte slice; they return `bool` and do not record the value.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::bytes::Regex;

pub mod validators;

mod asia;
mod europe;
mod gcc;
mod global;

/// A single DLP pattern: a regex pre-filter wrapped around a
/// structural validator. Both run inside the scanner; matched bytes
/// are never serialised onto the event bus.
pub struct PatternDef {
    /// Stable category identifier, e.g. `"pii.ssn"`.
    pub category: &'static str,
    /// Region tag used for regional glob selection. One of
    /// `"asia" | "gcc" | "europe" | "global"`.
    pub region: &'static str,
    /// Human-readable name used in logs and tracing.
    pub name: &'static str,
    /// Byte-oriented regex pre-filter. The scanner runs each
    /// pattern's regex individually (see [`crate::scanner::Scanner`])
    /// rather than unioning the catalogue into a `regex::bytes::RegexSet`,
    /// because each match must carry its originating category through
    /// to the validator. Per-pattern compilation also keeps the
    /// memory profile predictable when operators select a subset of
    /// the catalogue via [`select`].
    pub regex: Regex,
    /// Structural validator over the matched byte slice. Returns
    /// `true` when the candidate is structurally valid.
    pub validator: fn(&[u8]) -> bool,
}

impl PatternDef {
    /// Run the structural validator on `bytes`. Returns `true` only
    /// when both the regex matched (assumed by caller) AND the
    /// validator accepts the slice.
    #[inline]
    pub fn validate(&self, bytes: &[u8]) -> bool {
        (self.validator)(bytes)
    }
}

/// The full built-in pattern catalogue. The scanner iterates these
/// patterns individually and runs each regex over the input buffer;
/// see [`crate::scanner::Scanner`] for the rationale (per-pattern
/// matches must preserve their originating category for the
/// validator and the downstream `LocalDetectionAlert`).
///
/// The function is cheap and deterministic, but each call recompiles
/// the regexes. Production code keeps one instance around in the
/// scanner; test code can call it freely.
pub fn baseline_patterns() -> Vec<PatternDef> {
    let mut out = Vec::with_capacity(50);
    out.extend(global::patterns());
    out.extend(asia::patterns());
    out.extend(gcc::patterns());
    out.extend(europe::patterns());
    out
}

/// Returns `true` if `pattern_id` is something `select` would
/// recognise (an exact built-in category, a known regional or
/// category-prefix glob, or the `*` wildcard). Used by
/// `DlpConfig::patterns` to drop typos before the scanner is
/// constructed.
pub fn is_builtin_category(pattern_id: &str) -> bool {
    if pattern_id == "*" || pattern_id == "all" {
        return true;
    }
    if let Some(prefix) = pattern_id.strip_suffix(".*") {
        // Either the regional namespace or the category-tag prefix
        // must match at least one registered pattern.
        let cats = known_categories();
        let regions = known_regions();
        return regions.contains(prefix) || cats.iter().any(|c| category_has_prefix(c, prefix));
    }
    known_categories().contains(pattern_id)
}

/// Build a pattern set restricted to `selected` selectors.
///
/// Unknown / typo'd selectors are silently dropped so a bad config
/// can't take down the module. The caller (DLP module) logs a
/// warning when this happens. An empty selection returns every
/// pattern in the catalogue.
pub fn select(selected: &[String]) -> Vec<PatternDef> {
    let all = baseline_patterns();
    if selected.is_empty() {
        return all;
    }
    if selected.iter().any(|s| s == "*" || s == "all") {
        return all;
    }
    all.into_iter()
        .filter(|p| selected.iter().any(|s| matches_selector(s, p)))
        .collect()
}

/// Expand the `DlpConfig::region` shorthand into a glob list usable
/// with [`select`]. Returns `None` when the shorthand is empty or
/// unrecognised so the caller falls back to its own defaults.
pub fn expand_region(region: &str) -> Option<Vec<String>> {
    let trimmed = region.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "" => None,
        "all" | "*" => Some(vec!["*".to_string()]),
        other if known_regions().contains(other) => Some(vec![format!("{other}.*")]),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn matches_selector(selector: &str, p: &PatternDef) -> bool {
    if selector == "*" || selector == "all" {
        return true;
    }
    if let Some(prefix) = selector.strip_suffix(".*") {
        if prefix == p.region {
            return true;
        }
        return category_has_prefix(p.category, prefix);
    }
    selector == p.category
}

fn category_has_prefix(category: &str, prefix: &str) -> bool {
    category.len() > prefix.len()
        && category.as_bytes()[..prefix.len()] == *prefix.as_bytes()
        && category.as_bytes()[prefix.len()] == b'.'
}

fn known_categories() -> &'static HashSet<&'static str> {
    // Built from the static `CATEGORIES` lists each region module
    // ships alongside its `patterns()` constructor. That keeps this
    // path off the regex-compilation critical path even when the
    // scanner hasn't initialised yet — only the per-region
    // `&'static [&'static str]` slices are touched.
    //
    // A `category_list_matches_pattern_catalogue` unit test enforces
    // that this list stays in lock-step with `patterns()`.
    static CATS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    CATS.get_or_init(|| {
        let mut set = HashSet::with_capacity(
            asia::CATEGORIES.len()
                + gcc::CATEGORIES.len()
                + europe::CATEGORIES.len()
                + global::CATEGORIES.len(),
        );
        set.extend(asia::CATEGORIES.iter().copied());
        set.extend(gcc::CATEGORIES.iter().copied());
        set.extend(europe::CATEGORIES.iter().copied());
        set.extend(global::CATEGORIES.iter().copied());
        set
    })
}

fn known_regions() -> &'static HashSet<&'static str> {
    static REGIONS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    REGIONS.get_or_init(|| {
        let mut r = HashSet::new();
        r.insert("asia");
        r.insert("gcc");
        r.insert("europe");
        r.insert("global");
        r
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalogue currently ships exactly 50 patterns:
    ///   16 Asia + 8 GCC + 13 Europe + 13 Global = 50.
    #[test]
    fn baseline_patterns_have_expected_count() {
        let p = baseline_patterns();
        assert_eq!(
            p.len(),
            50,
            "expected 50 baseline patterns, got {}",
            p.len()
        );
        // Spot-check region coverage.
        for region in ["asia", "gcc", "europe", "global"] {
            assert!(
                p.iter().any(|d| d.region == region),
                "missing region: {region}"
            );
        }
    }

    #[test]
    fn baseline_categories_are_unique() {
        let all = baseline_patterns();
        let mut seen = HashSet::new();
        for d in &all {
            assert!(
                seen.insert(d.category),
                "duplicate category in catalogue: {}",
                d.category
            );
        }
    }

    /// Drift guard: the static `CATEGORIES` arrays each region module
    /// exposes must list every category that the live `patterns()`
    /// constructor returns. `known_categories()` relies on this so it
    /// can answer `is_builtin_category` without compiling any regex.
    #[test]
    fn category_list_matches_pattern_catalogue() {
        let live: HashSet<&'static str> = baseline_patterns().iter().map(|p| p.category).collect();
        let mut declared: HashSet<&'static str> = HashSet::new();
        declared.extend(asia::CATEGORIES.iter().copied());
        declared.extend(gcc::CATEGORIES.iter().copied());
        declared.extend(europe::CATEGORIES.iter().copied());
        declared.extend(global::CATEGORIES.iter().copied());
        let only_live: Vec<_> = live.difference(&declared).copied().collect();
        let only_declared: Vec<_> = declared.difference(&live).copied().collect();
        assert!(
            only_live.is_empty() && only_declared.is_empty(),
            "category lists drifted: only in patterns()={only_live:?}, only in CATEGORIES={only_declared:?}",
        );
    }

    #[test]
    fn is_builtin_category_recognises_legacy_and_new_ids() {
        assert!(is_builtin_category("pii.ssn"));
        assert!(is_builtin_category("pii.uk_ni"));
        assert!(is_builtin_category("pci.pan_luhn"));
        assert!(is_builtin_category("pii.in_aadhaar"));
        assert!(is_builtin_category("pii.sg_nric"));
        assert!(is_builtin_category("secrets.jwt"));
        assert!(!is_builtin_category("nope"));
        assert!(!is_builtin_category("pii.does_not_exist"));
    }

    #[test]
    fn is_builtin_category_accepts_glob_selectors() {
        assert!(is_builtin_category("asia.*"));
        assert!(is_builtin_category("gcc.*"));
        assert!(is_builtin_category("europe.*"));
        assert!(is_builtin_category("global.*"));
        assert!(is_builtin_category("pii.*"));
        assert!(is_builtin_category("pci.*"));
        assert!(is_builtin_category("secrets.*"));
        assert!(is_builtin_category("*"));
        assert!(is_builtin_category("all"));
        assert!(!is_builtin_category("xyz.*"));
    }

    #[test]
    fn select_empty_returns_full_catalogue() {
        let all = select(&[]);
        assert_eq!(all.len(), baseline_patterns().len());
    }

    #[test]
    fn select_exact_category_returns_single_match() {
        let only_ssn = select(&["pii.ssn".to_string()]);
        assert_eq!(only_ssn.len(), 1);
        assert_eq!(only_ssn[0].category, "pii.ssn");
    }

    #[test]
    fn select_regional_glob_returns_region_only() {
        let asia = select(&["asia.*".to_string()]);
        assert!(!asia.is_empty());
        assert!(asia.iter().all(|p| p.region == "asia"));
        assert_eq!(asia.len(), 16);
    }

    #[test]
    fn select_category_prefix_glob_returns_prefix_matches() {
        let pci = select(&["pci.*".to_string()]);
        assert!(!pci.is_empty());
        assert!(pci.iter().all(|p| p.category.starts_with("pci.")));
        let secrets = select(&["secrets.*".to_string()]);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().all(|p| p.category.starts_with("secrets.")));
    }

    #[test]
    fn select_combines_globs_and_exact_ids() {
        let mixed = select(&[
            "asia.*".to_string(),
            "pci.pan_luhn".to_string(),
            "secrets.jwt".to_string(),
        ]);
        assert!(mixed.iter().any(|p| p.category == "pci.pan_luhn"));
        assert!(mixed.iter().any(|p| p.category == "secrets.jwt"));
        assert!(mixed.iter().filter(|p| p.region == "asia").count() == 16);
    }

    #[test]
    fn select_wildcard_returns_full_catalogue() {
        assert_eq!(select(&["*".to_string()]).len(), baseline_patterns().len());
        assert_eq!(
            select(&["all".to_string()]).len(),
            baseline_patterns().len()
        );
    }

    #[test]
    fn expand_region_handles_shorthand() {
        assert_eq!(expand_region("asia"), Some(vec!["asia.*".to_string()]));
        assert_eq!(expand_region("Europe"), Some(vec!["europe.*".to_string()]));
        assert_eq!(expand_region(" gcc "), Some(vec!["gcc.*".to_string()]));
        assert_eq!(expand_region("all"), Some(vec!["*".to_string()]));
        assert_eq!(expand_region(""), None);
        assert_eq!(expand_region("antarctica"), None);
    }
}
