//! Behavioural rule engine.
//!
//! Evaluates the behavioural section of the rule bundle against a
//! stream of events.  Two matcher variants are implemented today:
//!
//! * **Threshold** — fire when a keyed entity observes the same
//!   pattern ≥ `min_count` times inside a sliding window.
//! * **Sequence** — fire when a keyed entity observes the configured
//!   ordered substrings inside a sliding window.
//!
//! State is bounded by `max_tracked_entities`: the oldest-inserted
//! entity is evicted when the limit is exceeded — the state maps are
//! backed by [`IndexMap`] so `keys()` iterates in deterministic
//! insertion order and eviction always targets the stalest entries
//! rather than an arbitrary hash-bucket victim.  Windows older than
//! `max_window_sec` are purged on every evaluation.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use indexmap::IndexMap;
use regex::Regex;
use tracing::warn;

use crate::rule_store::{BehavioralRule, BehavioralRuleKind};

/// A behavioural match raised by [`BehavioralEngine::evaluate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehavioralMatch {
    pub rule_id: String,
    pub severity: String,
    pub description: String,
    /// The entity (source/key) that tripped the rule.
    pub entity: String,
}

/// An input event for the behavioural engine — either FIM or
/// logcollector derived.
#[derive(Debug, Clone)]
pub struct BehavioralEvent<'a> {
    /// `"fim"` or `"logcollector"`.
    pub source: &'a str,
    /// Stable entity identifier — for logs, the log source/file; for
    /// FIM the changed path.
    pub entity: &'a str,
    /// Free-form text searched by `contains` / `sequence` predicates.
    pub text: &'a str,
}

/// Compiled behavioural state machine.
pub struct BehavioralEngine {
    rules: Vec<BehavioralRule>,
    // Per-rule, per-entity state.  A simple linear index in `rules`
    // keeps the hash key compact.  `IndexMap` preserves insertion
    // order so eviction deterministically removes the oldest entries
    // rather than arbitrary hash-bucket victims.
    threshold_state: IndexMap<(usize, String), VecDeque<Instant>>,
    sequence_state: IndexMap<(usize, String), SequenceState>,
    /// Compiled `(name_regex, parent_chain_regex)` pairs for the
    /// `ProcessChain` matcher, indexed by rule offset in `rules`.  We
    /// compile once at construction time so each event evaluation is
    /// a simple lookup.
    process_chain_regex: HashMap<usize, (Regex, Regex)>,
    max_entities: usize,
    max_window: Duration,
}

/// Progress tracker for a pending sequence match.
#[derive(Debug, Clone)]
struct SequenceState {
    position: usize,
    started_at: Instant,
}

impl BehavioralEngine {
    /// Build an engine from the provided rule list.
    pub fn new(rules: Vec<BehavioralRule>, max_entities: usize, max_window_sec: u64) -> Self {
        let mut process_chain_regex = HashMap::new();
        for (idx, rule) in rules.iter().enumerate() {
            if let BehavioralRuleKind::ProcessChain {
                name_regex,
                parent_chain_regex,
            } = &rule.kind
            {
                match (Regex::new(name_regex), Regex::new(parent_chain_regex)) {
                    (Ok(n), Ok(p)) => {
                        process_chain_regex.insert(idx, (n, p));
                    }
                    (n, p) => {
                        if let Err(e) = n {
                            warn!(
                                rule = %rule.id,
                                error = %e,
                                "behavioural rule has invalid name_regex; skipping"
                            );
                        }
                        if let Err(e) = p {
                            warn!(
                                rule = %rule.id,
                                error = %e,
                                "behavioural rule has invalid parent_chain_regex; skipping"
                            );
                        }
                    }
                }
            }
        }
        Self {
            rules,
            threshold_state: IndexMap::new(),
            sequence_state: IndexMap::new(),
            process_chain_regex,
            max_entities: max_entities.max(1),
            max_window: Duration::from_secs(max_window_sec.max(1)),
        }
    }

    /// Feed an event and return any rule matches triggered by it.
    pub fn evaluate(&mut self, event: &BehavioralEvent<'_>) -> Vec<BehavioralMatch> {
        self.evaluate_at(event, Instant::now())
    }

    /// Like [`evaluate`](Self::evaluate) but with an explicit clock,
    /// used by tests to drive the sliding window deterministically.
    pub fn evaluate_at(
        &mut self,
        event: &BehavioralEvent<'_>,
        now: Instant,
    ) -> Vec<BehavioralMatch> {
        let mut out = Vec::new();

        // Collect matches rule-by-rule using explicit indices so the
        // borrow checker lets us mutate the per-rule state below.
        for idx in 0..self.rules.len() {
            let rule = self.rules[idx].clone();
            if rule.event_source != event.source {
                continue;
            }

            match rule.kind.clone() {
                BehavioralRuleKind::Threshold {
                    contains,
                    min_count,
                    window_secs,
                } => {
                    if !event.text.contains(&contains) {
                        continue;
                    }
                    let window = Duration::from_secs(window_secs).min(self.max_window);
                    let key = (idx, event.entity.to_string());
                    let deque = self.threshold_state.entry(key.clone()).or_default();
                    deque.push_back(now);
                    // Drop events that fell out of the window.
                    while let Some(front) = deque.front().copied() {
                        if now.duration_since(front) > window {
                            deque.pop_front();
                        } else {
                            break;
                        }
                    }
                    if deque.len() as u32 >= min_count {
                        out.push(BehavioralMatch {
                            rule_id: rule.id.clone(),
                            severity: rule.severity.clone(),
                            description: rule.description.clone(),
                            entity: event.entity.to_string(),
                        });
                        // Reset so a single match doesn't keep firing
                        // on every subsequent event.
                        deque.clear();
                    }
                    self.maybe_evict(true);
                }
                BehavioralRuleKind::Sequence {
                    sequence,
                    window_secs,
                } => {
                    if sequence.is_empty() {
                        continue;
                    }
                    let window = Duration::from_secs(window_secs).min(self.max_window);
                    let key = (idx, event.entity.to_string());
                    let mut state =
                        self.sequence_state
                            .shift_remove(&key)
                            .unwrap_or(SequenceState {
                                position: 0,
                                started_at: now,
                            });

                    if now.duration_since(state.started_at) > window {
                        state = SequenceState {
                            position: 0,
                            started_at: now,
                        };
                    }

                    let expected = &sequence[state.position];
                    if event.text.contains(expected) {
                        if state.position == 0 {
                            state.started_at = now;
                        }
                        state.position += 1;
                        if state.position >= sequence.len() {
                            out.push(BehavioralMatch {
                                rule_id: rule.id.clone(),
                                severity: rule.severity.clone(),
                                description: rule.description.clone(),
                                entity: event.entity.to_string(),
                            });
                            // Reset so the sequence can re-arm.
                            continue;
                        }
                    }
                    self.sequence_state.insert(key, state);
                    self.maybe_evict(false);
                }
                BehavioralRuleKind::ProcessChain { .. } => {
                    // The process arm of handle_event packs the
                    // matched process name + cmdline AND the
                    // " > "-joined parent chain into `event.text`,
                    // separated by " > " when a chain is present.
                    // The entity is the spawned process's exe_path
                    // (or name as a fallback).
                    let Some((name_re, chain_re)) = self.process_chain_regex.get(&idx) else {
                        continue;
                    };
                    let (chain_part, leaf_part) = split_chain_and_leaf(event.text);
                    if !name_re.is_match(leaf_part) {
                        continue;
                    }
                    if !chain_re.is_match(chain_part) {
                        continue;
                    }
                    out.push(BehavioralMatch {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        description: rule.description.clone(),
                        entity: event.entity.to_string(),
                    });
                }
            }
        }
        out
    }

    /// Enforce the `max_tracked_entities` cap by evicting the
    /// oldest-inserted entries once the map grows past the limit.
    /// Backing the state maps with [`IndexMap`] means `drain(0..n)`
    /// drops the `n` stalest entries rather than arbitrary hash-bucket
    /// victims.
    fn maybe_evict(&mut self, touched_threshold: bool) {
        let len = if touched_threshold {
            self.threshold_state.len()
        } else {
            self.sequence_state.len()
        };
        if len <= self.max_entities {
            return;
        }
        let victims = len - self.max_entities;
        if touched_threshold {
            self.threshold_state.drain(..victims);
        } else {
            self.sequence_state.drain(..victims);
        }
    }

    /// Current number of tracked entity states (for observability).
    pub fn tracked_entities(&self) -> usize {
        self.threshold_state.len() + self.sequence_state.len()
    }
}

/// Split a process-arm primary_text into `(chain, leaf_name)` for
/// independent name- and chain-regex matching.
///
/// `handle_event` builds the primary_text as either:
///   `"parent1 > parent2 > name cmdline…"`  (with chain)
///   `"name cmdline…"`                       (no chain)
///
/// We split on the *last* `" > "` to separate the chain from the
/// leaf, then take the first whitespace-delimited token of the leaf
/// as the process name (since the remainder is cmdline text).
fn split_chain_and_leaf(text: &str) -> (&str, &str) {
    let (chain, leaf) = if let Some(idx) = text.rfind(" > ") {
        (&text[..idx], &text[idx + 3..])
    } else {
        ("", text)
    };
    // Extract just the process name (first token) from the leaf.
    let leaf_name = leaf.split_whitespace().next().unwrap_or("");
    (chain, leaf_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_store::SEV_MEDIUM;

    fn threshold_rule(id: &str, contains: &str, min: u32, window: u64) -> BehavioralRule {
        BehavioralRule {
            id: id.into(),
            severity: SEV_MEDIUM.into(),
            description: "test".into(),
            event_source: "logcollector".into(),
            kind: BehavioralRuleKind::Threshold {
                contains: contains.into(),
                min_count: min,
                window_secs: window,
            },
        }
    }

    fn sequence_rule(id: &str, steps: &[&str], window: u64) -> BehavioralRule {
        BehavioralRule {
            id: id.into(),
            severity: SEV_MEDIUM.into(),
            description: "test".into(),
            event_source: "logcollector".into(),
            kind: BehavioralRuleKind::Sequence {
                sequence: steps.iter().map(|s| s.to_string()).collect(),
                window_secs: window,
            },
        }
    }

    fn process_chain_rule(id: &str, name_re: &str, chain_re: &str, desc: &str) -> BehavioralRule {
        use crate::rule_store::SEV_HIGH;
        BehavioralRule {
            id: id.into(),
            severity: SEV_HIGH.into(),
            description: desc.into(),
            // Phase E review: ProcessChain rules are pinned to the
            // `process_created` source so they cannot fire on
            // ProcessTerminated / ImageLoaded events.
            event_source: "process_created".into(),
            kind: BehavioralRuleKind::ProcessChain {
                name_regex: name_re.into(),
                parent_chain_regex: chain_re.into(),
            },
        }
    }

    #[test]
    fn test_threshold_fires_after_min_count() {
        let mut eng = BehavioralEngine::new(
            vec![threshold_rule("brute-ssh", "auth failure", 3, 60)],
            100,
            3600,
        );
        let t0 = Instant::now();
        let ev = BehavioralEvent {
            source: "logcollector",
            entity: "sshd",
            text: "auth failure for user root",
        };
        assert!(eng.evaluate_at(&ev, t0).is_empty());
        assert!(eng.evaluate_at(&ev, t0 + Duration::from_secs(1)).is_empty());
        let hits = eng.evaluate_at(&ev, t0 + Duration::from_secs(2));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "brute-ssh");
        assert_eq!(hits[0].entity, "sshd");
    }

    #[test]
    fn test_threshold_window_expiry_resets_count() {
        let mut eng = BehavioralEngine::new(
            vec![threshold_rule("brute-ssh", "auth failure", 3, 60)],
            100,
            3600,
        );
        let t0 = Instant::now();
        let ev = BehavioralEvent {
            source: "logcollector",
            entity: "sshd",
            text: "auth failure",
        };
        eng.evaluate_at(&ev, t0);
        eng.evaluate_at(&ev, t0 + Duration::from_secs(1));
        // Jump forward past the window — old events should be dropped.
        let hits = eng.evaluate_at(&ev, t0 + Duration::from_secs(120));
        assert!(hits.is_empty(), "count should have reset");
    }

    #[test]
    fn test_sequence_detection_in_order() {
        let mut eng = BehavioralEngine::new(
            vec![sequence_rule(
                "exfil",
                &["download", "compress", "upload"],
                60,
            )],
            100,
            3600,
        );
        let t0 = Instant::now();
        let base = BehavioralEvent {
            source: "logcollector",
            entity: "host",
            text: "",
        };

        assert!(eng
            .evaluate_at(
                &BehavioralEvent {
                    text: "download starts",
                    ..base
                },
                t0
            )
            .is_empty());
        assert!(eng
            .evaluate_at(
                &BehavioralEvent {
                    text: "compress data",
                    ..base
                },
                t0 + Duration::from_secs(1)
            )
            .is_empty());
        let hits = eng.evaluate_at(
            &BehavioralEvent {
                text: "upload complete",
                ..base
            },
            t0 + Duration::from_secs(2),
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "exfil");
    }

    #[test]
    fn test_sequence_resets_after_window_expiry() {
        let mut eng = BehavioralEngine::new(
            vec![sequence_rule("exfil", &["a", "b", "c"], 10)],
            100,
            3600,
        );
        let t0 = Instant::now();
        eng.evaluate_at(
            &BehavioralEvent {
                source: "logcollector",
                entity: "host",
                text: "a",
            },
            t0,
        );
        // Later than the 10-second window — progress must reset.
        let hits = eng.evaluate_at(
            &BehavioralEvent {
                source: "logcollector",
                entity: "host",
                text: "c",
            },
            t0 + Duration::from_secs(30),
        );
        assert!(hits.is_empty(), "sequence must not skip steps");
    }

    #[test]
    fn test_source_filter_ignores_other_sources() {
        let mut eng =
            BehavioralEngine::new(vec![threshold_rule("log-only", "x", 1, 60)], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "fim",
            entity: "/etc",
            text: "x",
        });
        assert!(hits.is_empty());
    }

    #[test]
    fn test_tracked_entities_cap_evicts() {
        let mut eng = BehavioralEngine::new(vec![threshold_rule("t", "x", 99, 60)], 2, 3600);
        let t0 = Instant::now();
        for i in 0..10 {
            let e = format!("host-{i}");
            eng.evaluate_at(
                &BehavioralEvent {
                    source: "logcollector",
                    entity: &e,
                    text: "x",
                },
                t0,
            );
        }
        assert!(
            eng.tracked_entities() <= 2,
            "eviction should hold to max_entities (got {})",
            eng.tracked_entities()
        );
    }

    #[test]
    fn test_eviction_drops_oldest_inserted_first() {
        // Regression — eviction must be deterministic (oldest-inserted
        // first), not driven by arbitrary hash-bucket order.  We insert
        // entities in a known sequence, overflow the cap, and verify the
        // survivors are precisely the most recently inserted entries.
        let mut eng = BehavioralEngine::new(vec![threshold_rule("t", "x", 99, 60)], 3, 3600);
        let t0 = Instant::now();
        let order = ["a", "b", "c", "d", "e"];
        for name in &order {
            eng.evaluate_at(
                &BehavioralEvent {
                    source: "logcollector",
                    entity: name,
                    text: "x",
                },
                t0,
            );
        }
        assert_eq!(eng.tracked_entities(), 3);
        let surviving: Vec<&str> = eng
            .threshold_state
            .keys()
            .map(|(_, e)| e.as_str())
            .collect();
        assert_eq!(surviving, vec!["c", "d", "e"]);
    }

    // --- ProcessChain matcher tests (Phase E1.7) ---

    #[test]
    fn test_process_chain_office_spawns_powershell() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*(winword|excel|outlook)(\.exe)?.*",
            "Office app spawned PowerShell",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            text: "explorer.exe > winword.exe > cmd.exe > powershell.exe -enc ...",
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "edr-chain-001");
    }

    #[test]
    fn test_process_chain_no_match_benign_parent() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*(winword|excel|outlook)(\.exe)?.*",
            "Office app spawned PowerShell",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            text: "explorer.exe > cmd.exe > powershell.exe",
        });
        assert!(hits.is_empty(), "benign parent chain should not match");
    }

    #[test]
    fn test_process_chain_wmiprvse_rundll32() {
        let rule = process_chain_rule(
            "edr-chain-002",
            r"^rundll32(\.exe)?$",
            r".*wmiprvse(\.exe)?.*",
            "wmiprvse spawned rundll32",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\rundll32.exe",
            text: "svchost.exe > wmiprvse.exe > rundll32.exe some.dll,entry",
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "edr-chain-002");
    }

    #[test]
    fn test_process_chain_source_filter() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*winword(\.exe)?.*",
            "test",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "logcollector",
            entity: "powershell.exe",
            text: "winword.exe > powershell.exe",
        });
        assert!(hits.is_empty(), "wrong source should be ignored");
    }

    #[test]
    fn test_process_chain_no_parent_chain() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*winword(\.exe)?.*",
            "test",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: "powershell.exe",
            text: "powershell.exe -enc ...",
        });
        assert!(hits.is_empty(), "empty chain should not match chain regex");
    }

    /// Regression for the Phase E review: ProcessChain rules MUST
    /// NOT fire on `ProcessTerminated` or `ImageLoaded` events even
    /// though the underlying domain ("process") is shared.  We
    /// enforce this by source-tag separation in `handle_event`; this
    /// test pins the invariant in the engine's tests.
    #[test]
    fn test_process_chain_ignores_terminated_and_image_loaded_sources() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*winword(\.exe)?.*",
            "Office app spawned PowerShell",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);

        // Synthetic ProcessTerminated payload: leaf is "terminated"
        // so the name regex would not match even if we forgot the
        // source pin; the source pin is the primary guard.
        let terminated = eng.evaluate(&BehavioralEvent {
            source: "process_terminated",
            entity: "powershell.exe",
            text: "explorer.exe > winword.exe > powershell.exe terminated exit_code=0",
        });
        assert!(
            terminated.is_empty(),
            "ProcessChain rule must not fire on process_terminated source"
        );

        // Synthetic ImageLoaded payload — same shape, different
        // source tag.  The engine should ignore the event entirely.
        let image_loaded = eng.evaluate(&BehavioralEvent {
            source: "process_image_loaded",
            entity: r"C:\Windows\System32\powershell.exe",
            text: "explorer.exe > winword.exe > powershell.exe",
        });
        assert!(
            image_loaded.is_empty(),
            "ProcessChain rule must not fire on process_image_loaded source"
        );

        // Sanity: the same chain DOES fire when the source is the
        // pinned `process_created`.
        let created = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\powershell.exe",
            text: "explorer.exe > winword.exe > powershell.exe",
        });
        assert_eq!(
            created.len(),
            1,
            "ProcessChain rule must fire on process_created source"
        );
    }

    #[test]
    fn test_split_chain_and_leaf() {
        // Leaf strips cmdline so the name regex sees just the program.
        assert_eq!(
            split_chain_and_leaf("explorer.exe > winword.exe > powershell.exe -enc xyz"),
            ("explorer.exe > winword.exe", "powershell.exe")
        );
        assert_eq!(
            split_chain_and_leaf("powershell.exe -enc"),
            ("", "powershell.exe")
        );
        assert_eq!(
            split_chain_and_leaf("powershell.exe"),
            ("", "powershell.exe")
        );
        assert_eq!(split_chain_and_leaf(""), ("", ""));
    }
}
