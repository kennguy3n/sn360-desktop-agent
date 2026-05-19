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
    /// Structured process metadata for [`BehavioralRuleKind::ProcessChain`]
    /// matchers.  Set by `handle_event` only for `process_created`
    /// events; `None` for every other source (FIM, logcollector,
    /// network, DNS, process_terminated, process_image_loaded).
    ///
    /// Carrying the parent chain and the leaf name as separate
    /// fields — rather than packing them into the same `text` string
    /// — avoids an ambiguity that was discovered earlier: when `text` was
    /// `"{parent_chain} > {name} {cmdline}"` and cmdline contained
    /// a literal `>` (PowerShell `-Command "... > out.txt"`, bash
    /// redirects, build scripts), `rfind(" > ")` matched inside
    /// cmdline instead of at the chain→leaf boundary and the regex
    /// produced a false negative on legitimate detections.
    pub process: Option<ProcessFields<'a>>,
}

/// Structured process fields surfaced to the
/// [`BehavioralRuleKind::ProcessChain`] matcher.
#[derive(Debug, Clone, Copy)]
pub struct ProcessFields<'a> {
    /// `" > "`-joined parent chain (root → immediate parent), e.g.
    /// `"explorer.exe > winword.exe"`.  Empty when no parents are
    /// known.
    pub parent_chain: &'a str,
    /// The spawned process's leaf basename, e.g. `"powershell.exe"`.
    /// Empty when the process name is unknown.
    pub leaf_name: &'a str,
}

/// A behavioural rule that was rejected at engine-construction time
/// because one of its regexes failed to compile.  Surfaced via
/// [`BehavioralEngine::take_skipped_rules`] so the LDE can emit a
/// `LocalDetectionAlert` per skipped rule and an operator sees the
/// permanently-disabled rule beyond the startup `warn!` log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRule {
    /// The rule's stable identifier (e.g. `edr-process-chain-001`).
    pub rule_id: String,
    /// Human-readable explanation, suitable for the alert
    /// `description` field — typically `"invalid name_regex: ..."`
    /// or `"invalid parent_chain_regex: ..."`.
    pub reason: String,
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
    /// Rules dropped at construction because their regexes did not
    /// compile.  Drained at first call to
    /// [`take_skipped_rules`](Self::take_skipped_rules).
    skipped_rules: Vec<SkippedRule>,
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
        let mut skipped_rules: Vec<SkippedRule> = Vec::new();
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
                        // Record one `SkippedRule` per rule (not per
                        // bad regex) so an operator sees exactly one
                        // alert per permanently-disabled rule.  The
                        // `reason` string concatenates both regex
                        // diagnostics when both sides fail.
                        let mut reason = String::new();
                        if let Err(e) = n {
                            warn!(
                                rule = %rule.id,
                                error = %e,
                                "behavioural rule has invalid name_regex; skipping"
                            );
                            reason.push_str(&format!("invalid name_regex: {e}"));
                        }
                        if let Err(e) = p {
                            warn!(
                                rule = %rule.id,
                                error = %e,
                                "behavioural rule has invalid parent_chain_regex; skipping"
                            );
                            if !reason.is_empty() {
                                reason.push_str("; ");
                            }
                            reason.push_str(&format!("invalid parent_chain_regex: {e}"));
                        }
                        skipped_rules.push(SkippedRule {
                            rule_id: rule.id.clone(),
                            reason,
                        });
                    }
                }
            }
        }
        Self {
            rules,
            threshold_state: IndexMap::new(),
            sequence_state: IndexMap::new(),
            process_chain_regex,
            skipped_rules,
            max_entities: max_entities.max(1),
            max_window: Duration::from_secs(max_window_sec.max(1)),
        }
    }

    /// Drain the set of rules that this engine refused to load
    /// because their regexes did not compile.  Subsequent calls
    /// return an empty `Vec`.  The LDE calls this once after engine
    /// construction (and again after each TRDS hot-reload) and emits
    /// one `LocalDetectionAlert` per entry so the operator has SIEM
    /// visibility into permanently-disabled rules rather than only
    /// a startup `warn!` log.
    pub fn take_skipped_rules(&mut self) -> Vec<SkippedRule> {
        std::mem::take(&mut self.skipped_rules)
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
                    // ProcessChain matches on STRUCTURED fields
                    // (`event.process.parent_chain` and
                    // `event.process.leaf_name`) populated by
                    // `handle_event` for `process_created` events.
                    // The entity is the spawned process's exe_path
                    // (or name as a fallback).  If the producing
                    // source did not provide structured process
                    // fields, the rule cannot match — this is also
                    // the secondary guard that keeps ProcessChain
                    // rules from firing on `process_terminated` or
                    // `process_image_loaded` events.
                    let Some((name_re, chain_re)) = self.process_chain_regex.get(&idx) else {
                        continue;
                    };
                    let Some(proc) = event.process else {
                        continue;
                    };
                    if !name_re.is_match(proc.leaf_name) {
                        continue;
                    }
                    if !chain_re.is_match(proc.parent_chain) {
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
            process: None,
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
            process: None,
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
            process: None,
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
                process: None,
            },
            t0,
        );
        // Later than the 10-second window — progress must reset.
        let hits = eng.evaluate_at(
            &BehavioralEvent {
                source: "logcollector",
                entity: "host",
                text: "c",
                process: None,
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
            process: None,
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
                    process: None,
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
                    process: None,
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

    // --- ProcessChain matcher tests ---

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
            text: "powershell.exe -enc ...",
            process: Some(ProcessFields {
                parent_chain: "explorer.exe > winword.exe > cmd.exe",
                leaf_name: "powershell.exe",
            }),
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
            text: "powershell.exe",
            process: Some(ProcessFields {
                parent_chain: "explorer.exe > cmd.exe",
                leaf_name: "powershell.exe",
            }),
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
            text: "rundll32.exe some.dll,entry",
            process: Some(ProcessFields {
                parent_chain: "svchost.exe > wmiprvse.exe",
                leaf_name: "rundll32.exe",
            }),
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
            process: None,
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
            process: Some(ProcessFields {
                parent_chain: "",
                leaf_name: "powershell.exe",
            }),
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

        // Synthetic ProcessTerminated payload: the source pin is the
        // primary guard; `process: None` is the secondary guard the
        // ProcessChain matcher uses since terminated/image-loaded
        // events do not carry structured process fields.
        let terminated = eng.evaluate(&BehavioralEvent {
            source: "process_terminated",
            entity: "powershell.exe",
            text: "terminated exit_code=0",
            process: None,
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
            text: r"C:\Windows\System32\powershell.exe",
            process: None,
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
            text: "powershell.exe",
            process: Some(ProcessFields {
                parent_chain: "explorer.exe > winword.exe",
                leaf_name: "powershell.exe",
            }),
        });
        assert_eq!(
            created.len(),
            1,
            "ProcessChain rule must fire on process_created source"
        );
    }

    /// Regression: a ProcessChain
    /// rule with an uncompilable regex must (a) be excluded from the
    /// live `process_chain_regex` table, and (b) appear in the engine
    /// `take_skipped_rules()` drain so the LDE can emit a
    /// `LocalDetectionAlert` for operator visibility.
    #[test]
    fn test_invalid_process_chain_regex_is_skipped_and_surfaced() {
        // `(unbalanced` is a parse error in `regex`.
        let bad_name = process_chain_rule(
            "bad-name-regex",
            "(unbalanced",
            "explorer\\.exe",
            "rule with broken name_regex",
        );
        let bad_chain = process_chain_rule(
            "bad-chain-regex",
            "powershell\\.exe",
            "(unbalanced",
            "rule with broken parent_chain_regex",
        );
        let good = process_chain_rule(
            "office-spawns-powershell",
            "powershell\\.exe",
            "winword\\.exe",
            "office spawns powershell",
        );

        let mut eng = BehavioralEngine::new(vec![bad_name, bad_chain, good], 100, 3600);

        let skipped = eng.take_skipped_rules();
        assert_eq!(skipped.len(), 2, "both bad rules must surface");
        assert!(
            skipped
                .iter()
                .any(|s| s.rule_id == "bad-name-regex" && s.reason.contains("invalid name_regex")),
            "skipped set must include name_regex failure, got {skipped:?}"
        );
        assert!(
            skipped.iter().any(|s| s.rule_id == "bad-chain-regex"
                && s.reason.contains("invalid parent_chain_regex")),
            "skipped set must include parent_chain_regex failure, got {skipped:?}"
        );

        // Drain semantics: a second call returns empty (otherwise we
        // would re-publish the same alerts on every event tick).
        assert!(
            eng.take_skipped_rules().is_empty(),
            "take_skipped_rules must drain"
        );

        // The good rule still fires — invalid rules do not poison
        // the rest of the bundle.
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\powershell.exe",
            text: "powershell.exe",
            process: Some(ProcessFields {
                parent_chain: "winword.exe",
                leaf_name: "powershell.exe",
            }),
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "office-spawns-powershell");
    }

    /// Regression: a `ProcessCreated`
    /// whose cmdline contains a literal `>` (shell redirect, PowerShell
    /// `-Command "... > out"`, build script) MUST still match the
    /// ProcessChain rule.  Before the refactor, `primary_text` was
    /// `"{parent_chain} > {name} {cmdline}"` and `split_chain_and_leaf`
    /// used `rfind(" > ")` to recover `(chain, leaf)` — which would
    /// happily match a `" > "` inside the cmdline and yield the wrong
    /// leaf (the post-redirect token), producing a false negative on
    /// every cmdline-with-redirect.  The fix carries `parent_chain` and
    /// `leaf_name` as structured fields on `BehavioralEvent::process`
    /// so the matcher is no longer sensitive to cmdline content.
    #[test]
    fn test_process_chain_matches_when_cmdline_contains_literal_redirect() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*winword(\.exe)?.*",
            "Office app spawned PowerShell",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        // PowerShell `-Command` payload that contains a literal
        // `" > "` (shell redirect) deep inside its argv.  Under the
        // old rfind-based splitter this string would have produced
        // a leaf of `bar` and the name regex would fail.  With the
        // structured fields, the matcher only sees the explicit
        // `parent_chain` and `leaf_name` and the redirect is
        // irrelevant.
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            text: "powershell.exe -Command Get-Content foo > bar",
            process: Some(ProcessFields {
                parent_chain: "explorer.exe > winword.exe",
                leaf_name: "powershell.exe",
            }),
        });
        assert_eq!(
            hits.len(),
            1,
            "ProcessChain rule must fire even when cmdline contains a literal redirect"
        );
        assert_eq!(hits[0].rule_id, "edr-chain-001");
    }

    /// Companion: a `ProcessCreated` event with `process: None`
    /// (e.g. produced by a future PAL that does not yet surface
    /// `parent_chain`) MUST NOT fire a ProcessChain rule.  The
    /// structured-fields guard in the matcher is the only thing
    /// keeping us from regressing into the cmdline-collision bug.
    #[test]
    fn test_process_chain_requires_structured_process_fields() {
        let rule = process_chain_rule(
            "edr-chain-001",
            r"^powershell(\.exe)?$",
            r".*winword(\.exe)?.*",
            "Office app spawned PowerShell",
        );
        let mut eng = BehavioralEngine::new(vec![rule], 100, 3600);
        let hits = eng.evaluate(&BehavioralEvent {
            source: "process_created",
            entity: r"C:\Windows\System32\powershell.exe",
            // Even with the chain in the free-form text, the matcher
            // must refuse to fire without the structured fields.
            text: "winword.exe > powershell.exe",
            process: None,
        });
        assert!(
            hits.is_empty(),
            "ProcessChain rule must not fall back to parsing event.text when process: None"
        );
    }
}
