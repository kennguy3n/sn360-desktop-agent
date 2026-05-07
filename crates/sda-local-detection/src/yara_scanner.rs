//! YARA file scanner.
//!
//! Compiles the `.yar`/`.yara` files referenced in the rule bundle
//! into a single [`yara::Rules`] instance (cheap once, expensive per
//! load) and offers a rate-limited, file-size-bounded scanning API.
//!
//! All scans are offloaded to `tokio::task::spawn_blocking`: libyara is
//! synchronous and we never want to stall the Tokio reactor.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

/// A single YARA rule match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    /// Rule identifier (the name in the `.yar` file).
    pub rule_id: String,
    /// Space-separated tag list, if any.
    pub tags: Vec<String>,
}

/// Compiled YARA ruleset bundled with scan policy.
///
/// Cloning is cheap — the expensive [`yara::Rules`] object lives behind
/// an [`Arc`].
#[derive(Clone)]
pub struct YaraScanner {
    rules: Option<Arc<yara::Rules>>,
    rate: Arc<Mutex<RateWindow>>,
    max_file_size_bytes: u64,
    scan_timeout: Duration,
}

impl YaraScanner {
    /// Compile all `.yar`/`.yara` files at the provided paths into a
    /// single scanner.
    ///
    /// Non-existent or unreadable paths are logged and skipped so a
    /// single bad rule file doesn't take down the whole scanner.
    pub fn new(
        rule_paths: &[PathBuf],
        scans_per_sec: u32,
        max_file_size_mb: u64,
    ) -> anyhow::Result<Self> {
        let rules = compile_rules(rule_paths)?;
        Ok(Self {
            rules: rules.map(Arc::new),
            rate: Arc::new(Mutex::new(RateWindow::new(scans_per_sec))),
            max_file_size_bytes: max_file_size_mb.saturating_mul(1024 * 1024),
            scan_timeout: Duration::from_secs(30),
        })
    }

    /// Construct an empty scanner — useful when the rule bundle
    /// contains no YARA paths.
    pub fn empty(scans_per_sec: u32, max_file_size_mb: u64) -> Self {
        Self {
            rules: None,
            rate: Arc::new(Mutex::new(RateWindow::new(scans_per_sec))),
            max_file_size_bytes: max_file_size_mb.saturating_mul(1024 * 1024),
            scan_timeout: Duration::from_secs(30),
        }
    }

    /// Whether any rules were compiled into this scanner.
    pub fn has_rules(&self) -> bool {
        self.rules.is_some()
    }

    /// Asynchronously scan a file, honouring the rate limit and
    /// file-size cap.  Returns `Ok(Vec::new())` for skipped files
    /// (too big, rate-limited, or no rules).
    pub async fn scan_file(&self, path: &Path) -> anyhow::Result<Vec<YaraMatch>> {
        let Some(rules) = self.rules.clone() else {
            return Ok(Vec::new());
        };

        // Size cap — cheap metadata read, avoids slurping huge files.
        match tokio::fs::metadata(path).await {
            Ok(md) if md.len() > self.max_file_size_bytes => {
                debug!(
                    path = %path.display(),
                    size = md.len(),
                    cap = self.max_file_size_bytes,
                    "skipping YARA scan: file exceeds size cap"
                );
                return Ok(Vec::new());
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "YARA metadata lookup failed");
                return Ok(Vec::new());
            }
            _ => {}
        }

        // Rate limit — sleep to the next second boundary if the budget
        // is exhausted.  Performed on the async side so we don't hold
        // the blocking thread.  The MutexGuard is dropped before the
        // `.await` to keep the future `Send`.
        let wait = { self.rate.lock().unwrap().consume_or_wait() };
        if let Some(wait) = wait {
            debug!(wait_ms = wait.as_millis() as u64, "rate-limiting YARA scan");
            tokio::time::sleep(wait).await;
            // Reset the window after waiting so the next token is fresh.
            self.rate.lock().unwrap().reset();
        }

        let path_buf = path.to_path_buf();
        let timeout = self.scan_timeout;
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<YaraMatch>> {
            let timeout_secs = timeout.as_secs().min(i32::MAX as u64) as i32;
            let hits = rules
                .scan_file(&path_buf, timeout_secs)
                .map_err(|e| anyhow::anyhow!("yara scan failed: {}", e))?;
            Ok(hits
                .into_iter()
                .map(|r| YaraMatch {
                    rule_id: r.identifier.to_string(),
                    tags: r.tags.iter().map(|t| t.to_string()).collect(),
                })
                .collect())
        })
        .await
        .map_err(|e| anyhow::anyhow!("yara scan task panicked: {}", e))?;

        result
    }
}

/// Compile the provided rule paths into an optional [`yara::Rules`].
///
/// If a rule file fails to parse, the compiler is rebuilt from scratch
/// and every previously-successful file is re-added so the operator
/// never silently loses earlier rules.  `add_rules_file` consumes the
/// compiler on every call (success or failure), hence the slot-based
/// `Option<Compiler>` dance.
fn compile_rules(rule_paths: &[PathBuf]) -> anyhow::Result<Option<yara::Rules>> {
    let mut compiler = Some(
        yara::Compiler::new()
            .map_err(|e| anyhow::anyhow!("failed to init yara compiler: {}", e))?,
    );
    let mut accepted: Vec<&PathBuf> = Vec::new();
    for path in rule_paths {
        if !path.exists() {
            warn!(path = %path.display(), "yara rule path does not exist, skipping");
            continue;
        }
        let c = compiler.take().expect("compiler slot always full");
        match c.add_rules_file(path) {
            Ok(next) => {
                compiler = Some(next);
                accepted.push(path);
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to add yara rule file; restoring previously-accepted rules"
                );
                compiler = Some(rebuild_compiler_with(&accepted)?);
            }
        }
    }
    if accepted.is_empty() {
        return Ok(None);
    }
    let rules = compiler
        .expect("compiler slot always full after loop")
        .compile_rules()
        .map_err(|e| anyhow::anyhow!("failed to compile yara rules: {}", e))?;
    Ok(Some(rules))
}

/// Fresh compiler pre-loaded with the given (previously-successful)
/// rule paths.  Used to recover from a mid-stream `add_rules_file`
/// failure without dropping rules we already validated.
fn rebuild_compiler_with(paths: &[&PathBuf]) -> anyhow::Result<yara::Compiler> {
    let mut compiler = yara::Compiler::new()
        .map_err(|e| anyhow::anyhow!("failed to re-init yara compiler: {}", e))?;
    for p in paths {
        compiler = compiler.add_rules_file(p.as_path()).map_err(|e| {
            anyhow::anyhow!(
                "failed to re-add previously-accepted rule {}: {}",
                p.display(),
                e
            )
        })?;
    }
    Ok(compiler)
}

/// Simple 1-second sliding window rate limiter.
struct RateWindow {
    limit: u32,
    count: u32,
    window_started: Instant,
}

impl RateWindow {
    fn new(limit: u32) -> Self {
        Self {
            limit: limit.max(1),
            count: 0,
            window_started: Instant::now(),
        }
    }

    /// Consume one token.  Returns `Some(wait_duration)` when the
    /// caller should sleep before the token is actually available.
    fn consume_or_wait(&mut self) -> Option<Duration> {
        let window = Duration::from_secs(1);
        if self.window_started.elapsed() >= window {
            self.window_started = Instant::now();
            self.count = 0;
        }
        if self.count < self.limit {
            self.count += 1;
            None
        } else {
            let remaining = window.saturating_sub(self.window_started.elapsed());
            Some(remaining.max(Duration::from_millis(10)))
        }
    }

    fn reset(&mut self) {
        self.window_started = Instant::now();
        self.count = 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_rule(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn test_compiles_valid_rules_and_skips_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let rule = write_rule(
            dir.path(),
            "hello.yar",
            r#"rule HelloWorld { strings: $a = "hello" condition: $a }"#,
        );
        let missing = dir.path().join("does-not-exist.yar");
        let scanner = YaraScanner::new(&[rule, missing], 10, 10).unwrap();
        assert!(scanner.has_rules());
    }

    #[test]
    fn test_empty_rule_list_has_no_rules() {
        let s = YaraScanner::new(&[], 1, 10).unwrap();
        assert!(!s.has_rules());
    }

    #[tokio::test]
    async fn test_scan_file_matches() {
        let dir = tempfile::tempdir().unwrap();
        let rule = write_rule(
            dir.path(),
            "match.yar",
            r#"rule FindMarker { strings: $a = "SDA-LDE-MARKER" condition: $a }"#,
        );
        let scanner = YaraScanner::new(&[rule], 100, 10).unwrap();

        let target = dir.path().join("payload.bin");
        std::fs::write(&target, b"prefix SDA-LDE-MARKER suffix").unwrap();
        let hits = scanner.scan_file(&target).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "FindMarker");
    }

    #[tokio::test]
    async fn test_scan_file_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let rule = write_rule(
            dir.path(),
            "match.yar",
            r#"rule FindMarker { strings: $a = "SDA-LDE-MARKER" condition: $a }"#,
        );
        let scanner = YaraScanner::new(&[rule], 100, 10).unwrap();
        let target = dir.path().join("clean.bin");
        std::fs::write(&target, b"just benign bytes").unwrap();
        let hits = scanner.scan_file(&target).await.unwrap();
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn test_scan_skips_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let rule = write_rule(
            dir.path(),
            "match.yar",
            r#"rule FindMarker { strings: $a = "SDA-LDE-MARKER" condition: $a }"#,
        );
        // max_file_size_mb=0 → any non-empty file is skipped.
        let scanner = YaraScanner::new(&[rule], 100, 0).unwrap();
        let target = dir.path().join("payload.bin");
        std::fs::write(&target, b"SDA-LDE-MARKER content").unwrap();
        let hits = scanner.scan_file(&target).await.unwrap();
        assert!(hits.is_empty(), "oversized file should be skipped");
    }

    #[test]
    fn test_rate_limiter_blocks_after_budget_exhausted() {
        let mut w = RateWindow::new(2);
        assert!(w.consume_or_wait().is_none());
        assert!(w.consume_or_wait().is_none());
        let wait = w.consume_or_wait();
        assert!(wait.is_some(), "third consume should block");
    }

    #[test]
    fn test_rate_limiter_refills_after_window() {
        let mut w = RateWindow::new(1);
        assert!(w.consume_or_wait().is_none());
        assert!(w.consume_or_wait().is_some());
        w.window_started = Instant::now() - Duration::from_secs(2);
        assert!(w.consume_or_wait().is_none(), "window should have reset");
    }
}
