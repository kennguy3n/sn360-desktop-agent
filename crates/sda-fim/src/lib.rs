//! File Integrity Monitoring (FIM) module for the SN360 Desktop Agent.
//!
//! Monitors filesystem changes using OS-native notification APIs
//! (inotify/FSEvents/ReadDirectoryChangesW) and reports changes
//! to the event bus for server delivery.
//!
//! # Real-time pipeline
//!
//! Under burst workloads (e.g., 1000 files created in rapid
//! succession) a naive "collect metadata + hash + publish" loop
//! pushes peak CPU well above the <3% budget. This module keeps the
//! real-time path cheap by:
//!
//! 1. **Lazy hashing** — a file change event is emitted immediately
//!    with `hash_sha256: None` (metadata only). The SHA-256 digest is
//!    computed asynchronously on the blocking pool, and a follow-up
//!    event with the hash populated is emitted once it completes.
//! 2. **Rate limiting** — `max_hashes_per_sec` bounds how many hash
//!    jobs can be dispatched per second. When the budget is spent the
//!    loop sleeps to the next second boundary before dispatching more.
//! 3. **Event batching** — events accumulate in a small in-memory
//!    buffer and are flushed to the bus as a burst when either
//!    `batch_size` or `batch_timeout_ms` is reached.

pub mod batcher;
pub mod config;
pub mod db;
pub mod debounce;
pub mod event_format;
pub mod hasher;
pub mod idle;
pub mod rate_limiter;
pub mod scanner;
pub mod watcher;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use sda_core::config::AgentConfig;
use sda_core::module::{ModuleHandle, ModuleHealth, ModuleStatus};
use sda_core::signal::ShutdownSignal;
use sda_core::{PowerProfile, PowerProfileReceiver};
use sda_event_bus::{Event, EventBus, EventKind, Priority};

use crate::batcher::EventBatcher;
use crate::db::{FimEntry, StateDb};
use crate::event_format::{format_syscheck_event, ChangeType};
use crate::rate_limiter::RateLimiter;
use crate::watcher::DebouncedWatcher;

use sda_pal::types::FsEventKind;

/// Internal capacity for the hash-completion channel.
const HASH_RESULT_CHAN_CAP: usize = 1024;

// Encode ModuleStatus as a u8 for atomic access.
const STATUS_INITIALIZED: u8 = 0;
const STATUS_RUNNING: u8 = 1;
const STATUS_STOPPED: u8 = 2;
const STATUS_FAILED: u8 = 3;

/// File Integrity Monitoring module.
pub struct FimModule {
    status: AtomicU8,
}

impl FimModule {
    /// Start the FIM module, returning a `ModuleHandle` that owns the spawned task.
    ///
    /// `power_rx` delivers the active [`PowerProfile`] so the module can
    /// retune its scan interval and [`RateLimiter`] budget when the host
    /// transitions between AC/battery/critical states.
    pub fn start(
        config: &AgentConfig,
        bus: EventBus,
        shutdown: ShutdownSignal,
        power_rx: PowerProfileReceiver,
    ) -> ModuleHandle {
        let fim_config = config.modules.fim.clone();
        let status = std::sync::Arc::new(AtomicU8::new(STATUS_INITIALIZED));
        let task_status = std::sync::Arc::clone(&status);

        let task = tokio::spawn(async move {
            if let Err(e) = run(fim_config, bus, shutdown, power_rx, task_status.clone()).await {
                error!(error = %e, "FIM module failed");
                task_status.store(STATUS_FAILED, Ordering::Relaxed);
                return Err(e);
            }
            Ok(())
        });

        ModuleHandle::new("fim", task)
    }
}

/// Compute the effective baseline-scan interval for `profile`.
///
/// Multiplies the configured interval by `1.0 / profile.fim_scan_rate()`:
/// when scans are accelerated (`IdleAC`, rate `2.0`) the interval shrinks;
/// when they are reduced (`BatteryActive`, rate `0.5`) the interval
/// stretches. [`PowerProfile::CriticalBattery`] returns `None` — the caller
/// should pause baseline scans entirely.
fn effective_scan_interval(base: Duration, profile: PowerProfile) -> Option<Duration> {
    let rate = profile.fim_scan_rate();
    if rate <= 0.0 {
        return None;
    }
    let secs = (base.as_secs_f64() / rate).clamp(1.0, f64::from(u32::MAX));
    Some(Duration::from_secs_f64(secs))
}

/// Compute the effective `max_hashes_per_sec` for `profile`.
///
/// `0` preserves "unlimited" (the caller opted out of rate limiting via
/// `fim.max_hashes_per_sec = 0`). A `CriticalBattery` rate of `0.0`
/// collapses the budget to `1` rather than `0` — the latter would be
/// interpreted by [`RateLimiter`] as "disable rate limiting" and we
/// want the opposite behavior (maximum throttle).
fn effective_hash_budget(base: u32, profile: PowerProfile) -> u32 {
    if base == 0 {
        return 0;
    }
    let rate = profile.fim_scan_rate();
    if rate <= 0.0 {
        return 1;
    }
    let scaled = (f64::from(base) * rate).round();
    scaled.clamp(1.0, f64::from(u32::MAX)) as u32
}

impl sda_core::module::AgentModule for FimModule {
    fn name(&self) -> &'static str {
        "fim"
    }

    fn status(&self) -> ModuleStatus {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleStatus::Running,
            STATUS_STOPPED => ModuleStatus::Stopped,
            STATUS_FAILED => ModuleStatus::Failed,
            _ => ModuleStatus::Initialized,
        }
    }

    fn health(&self) -> ModuleHealth {
        match self.status.load(Ordering::Relaxed) {
            STATUS_RUNNING => ModuleHealth::Healthy,
            STATUS_FAILED => ModuleHealth::Unhealthy,
            _ => ModuleHealth::Healthy,
        }
    }
}

/// Collect file metadata into a `FimEntry`.
///
/// When `check_sha256` is `true` the returned entry includes the
/// file's SHA-256 digest. Pass `false` from the real-time path to
/// keep the hot loop off of blocking I/O — callers compute the hash
/// asynchronously via [`hash_file_async`] and patch the entry later.
fn collect_metadata(path: &Path, check_sha256: bool) -> anyhow::Result<FimEntry> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("failed to stat {}: {}", path.display(), e))?;

    let sha256 = if check_sha256 && meta.is_file() {
        Some(hasher::hash_file(path)?)
    } else {
        None
    };

    let size = meta.len() as i64;

    #[cfg(unix)]
    let (permissions, uid, gid, mtime, inode) = {
        use std::os::unix::fs::MetadataExt;
        (
            meta.mode() as i64,
            meta.uid() as i64,
            meta.gid() as i64,
            meta.mtime(),
            meta.ino() as i64,
        )
    };

    #[cfg(not(unix))]
    let (permissions, uid, gid, mtime, inode) = {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        (0i64, 0i64, 0i64, mtime, 0i64)
    };

    Ok(FimEntry {
        path: path.to_string_lossy().to_string(),
        sha256,
        size,
        permissions,
        uid,
        gid,
        mtime,
        inode,
        last_scan: chrono::Utc::now().to_rfc3339(),
    })
}

/// Determine whether a path should be hashed based on FIM directory configs.
fn should_check_sha256(path: &Path, directories: &[sda_core::config::FimDirectory]) -> bool {
    for dir in directories {
        let dir_path = Path::new(&dir.path);
        if path.starts_with(dir_path) {
            return dir.check_sha256;
        }
    }
    true // default to hashing
}

/// Result of an async SHA-256 computation for a previously-emitted
/// metadata-only event.
struct HashResult {
    /// Kind of change the original event described.
    kind: ChangeType,
    /// Whether the original event was delivered as
    /// `FileMetadataChanged` (as opposed to `FileModified` /
    /// `FileCreated`).
    metadata_only: bool,
    /// Snapshot of the DB entry *before* this event's metadata
    /// overwrote it.
    old_entry: Option<FimEntry>,
    /// The entry that was emitted with `hash_sha256: None`.
    new_entry: FimEntry,
    /// The computed hash, or `None` if hashing failed.
    hash: Option<String>,
}

/// Compute a file's SHA-256 on the blocking pool.
fn hash_file_async(path: PathBuf) -> tokio::task::JoinHandle<Option<String>> {
    tokio::task::spawn_blocking(move || match hasher::hash_file(&path) {
        Ok(h) => Some(h),
        Err(e) => {
            debug!(path = %path.display(), error = %e, "async hash failed");
            None
        }
    })
}

/// Build the `EventKind` for a given change + payload.
fn build_event_kind(
    change: ChangeType,
    metadata_only: bool,
    path: String,
    payload: String,
) -> EventKind {
    match change {
        ChangeType::Added => EventKind::FileCreated {
            path,
            syscheck_payload: Some(payload),
        },
        ChangeType::Deleted => EventKind::FileDeleted {
            path,
            syscheck_payload: Some(payload),
        },
        ChangeType::Modified => {
            if metadata_only {
                EventKind::FileMetadataChanged {
                    path,
                    syscheck_payload: Some(payload),
                }
            } else {
                EventKind::FileModified {
                    path,
                    syscheck_payload: Some(payload),
                }
            }
        }
    }
}

/// The main FIM run loop.
async fn run(
    fim_config: sda_core::config::FimConfig,
    bus: EventBus,
    mut shutdown: ShutdownSignal,
    mut power_rx: PowerProfileReceiver,
    status: std::sync::Arc<AtomicU8>,
) -> anyhow::Result<()> {
    info!("FIM module starting");

    // Open (or create) the state database.
    let db_path = config::default_db_path();
    let db = match StateDb::open(&db_path) {
        Ok(db) => {
            info!(path = %db_path.display(), "opened FIM state database");
            db
        }
        Err(e) => {
            warn!(error = %e, "failed to open FIM DB at default path, using in-memory fallback");
            StateDb::open_in_memory()?
        }
    };

    // Initialize the debounced watcher.
    let mut watcher = DebouncedWatcher::new(fim_config.debounce_ms)?;

    // Watch all configured directories.
    for dir in &fim_config.directories {
        let path = Path::new(&dir.path);
        if !path.exists() {
            warn!(path = %dir.path, "FIM directory does not exist, skipping");
            continue;
        }
        if let Err(e) = watcher.watch(path, dir.recursive) {
            error!(path = %dir.path, error = %e, "failed to watch directory");
        } else {
            info!(path = %dir.path, recursive = dir.recursive, "watching directory");
        }
    }

    status.store(STATUS_RUNNING, Ordering::Relaxed);
    info!("FIM module running");

    // Set up the baseline scan timer.
    //
    // The configured `scan_interval` is the baseline for a `Normal`
    // power profile; `rebuild_scan_timer` stretches or compresses it
    // based on the live profile, and returns `None` when the current
    // profile is `CriticalBattery` so the loop can pause scans.
    let base_scan_interval = Duration::from_secs(fim_config.scan_interval);
    let mut current_profile = *power_rx.borrow();
    let mut scan_timer = rebuild_scan_timer(base_scan_interval, current_profile);

    let scan_db_path: Option<PathBuf> = db.path();
    let scan_directories = fim_config.directories.clone();
    let scan_bus = bus.clone();

    // Run initial baseline scan on startup, unless the host is already
    // on critical battery in which case we defer until the profile
    // recovers.
    if current_profile.fim_scan_rate() > 0.0 {
        let db_path = scan_db_path.clone();
        let dirs = scan_directories.clone();
        let scan_bus = scan_bus.clone();
        tokio::spawn(async move {
            run_baseline_scan_task(db_path, dirs, scan_bus).await;
        });
    } else {
        info!(
            profile = ?current_profile,
            "skipping initial baseline scan: FIM paused under critical-battery profile"
        );
    }

    // Rate limiter + batcher for the real-time hashing pipeline.
    let base_max_hashes_per_sec = fim_config.max_hashes_per_sec;
    let mut rate_limiter = RateLimiter::new(effective_hash_budget(
        base_max_hashes_per_sec,
        current_profile,
    ));
    let mut batcher = EventBatcher::new(fim_config.batch_size, fim_config.batch_timeout_ms);

    // Internal channel for completed hash jobs. Bounded so a
    // misbehaving hash pool can't blow up memory; if the channel is
    // momentarily full we drop the follow-up event (the metadata
    // one was already delivered).
    let (hash_tx, mut hash_rx) = mpsc::channel::<HashResult>(HASH_RESULT_CHAN_CAP);

    // Main event loop.
    loop {
        let batch_deadline = batcher.deadline();

        tokio::select! {
            biased;

            _ = shutdown.wait() => {
                info!("FIM module received shutdown signal");
                batcher.flush(&bus).await;
                break;
            }

            change = power_rx.changed() => {
                if change.is_err() {
                    // Sender dropped; the agent is shutting down. Keep
                    // running with the last-known profile until the
                    // shutdown signal fires.
                    debug!("power-profile sender dropped, FIM holding last profile");
                    continue;
                }
                let new_profile = *power_rx.borrow();
                if new_profile == current_profile {
                    continue;
                }
                info!(
                    previous = ?current_profile,
                    current = ?new_profile,
                    "FIM retuning for new power profile"
                );
                current_profile = new_profile;
                scan_timer = rebuild_scan_timer(base_scan_interval, current_profile);
                rate_limiter.set_max_per_sec(effective_hash_budget(
                    base_max_hashes_per_sec,
                    current_profile,
                ));
            }

            _ = tick_scan_timer(scan_timer.as_mut()), if scan_timer.is_some() => {
                if current_profile.fim_scan_rate() <= 0.0 {
                    debug!(profile = ?current_profile, "FIM scan timer fired under paused profile; skipping scan");
                    continue;
                }
                info!(profile = ?current_profile, "baseline scan timer fired");
                let db_path = scan_db_path.clone();
                let dirs = scan_directories.clone();
                let scan_bus = scan_bus.clone();
                tokio::spawn(async move {
                    run_baseline_scan_task(db_path, dirs, scan_bus).await;
                });
            }

            Some(result) = hash_rx.recv() => {
                handle_hash_result(result, &db, &mut batcher);
                if batcher.is_full() {
                    batcher.flush(&bus).await;
                }
            }

            _ = sleep_until_deadline(batch_deadline), if batch_deadline.is_some() => {
                batcher.flush(&bus).await;
            }

            event = watcher.next_event() => {
                let event = match event {
                    Some(ev) => ev,
                    None => {
                        warn!("FIM watcher channel closed");
                        break;
                    }
                };

                let pending = process_fs_event(event, &fim_config, &db, &mut batcher);

                if batcher.is_full() {
                    batcher.flush(&bus).await;
                }

                for job in pending {
                    dispatch_hash_job(job, &mut rate_limiter, &hash_tx).await;
                }
            }
        }
    }

    status.store(STATUS_STOPPED, Ordering::Relaxed);
    info!("FIM module stopped");
    Ok(())
}

/// Construct a baseline-scan [`tokio::time::Interval`] for the given
/// profile, consuming the immediate first tick so the timer doesn't
/// fire a redundant scan right after startup. Returns `None` for
/// profiles that pause baseline scans entirely.
fn rebuild_scan_timer(base: Duration, profile: PowerProfile) -> Option<tokio::time::Interval> {
    let interval = effective_scan_interval(base, profile)?;
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    Some(timer)
}

/// Await the next tick on an optional interval. Only polled when the
/// `if timer.is_some()` guard in the select arm holds, so it is never
/// called with `None`.
async fn tick_scan_timer(timer: Option<&mut tokio::time::Interval>) {
    match timer {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Sleep until `deadline`, or wait forever if `deadline` is `None`.
async fn sleep_until_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// Parameters captured for a pending async hash computation.
struct PendingHashJob {
    kind: ChangeType,
    metadata_only: bool,
    old_entry: Option<FimEntry>,
    new_entry: FimEntry,
    path: PathBuf,
}

/// Handle one raw filesystem event from the debounced watcher.
///
/// This is the hot path under a burst and runs fully synchronously:
/// it never awaits while holding the `StateDb` borrow. Any hash
/// computation that needs to happen is returned as a list of
/// [`PendingHashJob`]s; the caller is responsible for dispatching
/// them through the rate-limited hash pool.
fn process_fs_event(
    event: sda_pal::types::FsEvent,
    fim_config: &sda_core::config::FimConfig,
    db: &StateDb,
    batcher: &mut EventBatcher,
) -> Vec<PendingHashJob> {
    let mut pending = Vec::new();
    let path = event.path.clone();
    let kind = event.kind;
    let check_sha256 = should_check_sha256(&path, &fim_config.directories);

    debug!(path = %path.display(), kind = ?kind, "processing FIM event");

    // File Integrity Monitoring targets files, not directories. Some
    // notify backends (notably macOS FSEvents/kqueue) emit a parent-
    // directory event alongside or instead of the child file event
    // when a file is created, modified, or removed inside a watched
    // directory. Forwarding those as `FileCreated` / `FileModified`
    // pollutes syscheck with alerts keyed on a directory path that
    // downstream consumers can't act on.
    if matches!(
        kind,
        FsEventKind::Created | FsEventKind::Modified | FsEventKind::MetadataChanged
    ) {
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.is_dir() {
                debug!(path = %path.display(), "skipping FIM event for directory");
                return pending;
            }
        }
    }

    match kind {
        FsEventKind::Created => {
            let path_str = path.to_string_lossy().to_string();
            let new_entry = match collect_metadata(&path, false) {
                Ok(entry) => entry,
                Err(e) => {
                    debug!(error = %e, path = %path_str, "file disappeared before stat");
                    return pending;
                }
            };

            if let Err(e) = db.upsert_entry(&new_entry) {
                warn!(error = %e, path = %path_str, "DB upsert failed");
            }

            let payload =
                format_syscheck_event(ChangeType::Added, &new_entry.path, None, Some(&new_entry));
            batcher.push(Event::new(
                "fim",
                Priority::Normal,
                build_event_kind(ChangeType::Added, false, path_str.clone(), payload),
            ));

            if check_sha256 && new_entry.sha256.is_none() {
                pending.push(PendingHashJob {
                    kind: ChangeType::Added,
                    metadata_only: false,
                    old_entry: None,
                    new_entry,
                    path,
                });
            }
        }

        FsEventKind::Modified | FsEventKind::MetadataChanged => {
            let path_str = path.to_string_lossy().to_string();
            let old_entry = match db.get_entry(&path_str) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, path = %path_str, "DB lookup failed");
                    return pending;
                }
            };

            let new_entry = match collect_metadata(&path, false) {
                Ok(entry) => entry,
                Err(e) => {
                    debug!(error = %e, path = %path_str, "file disappeared before stat");
                    return pending;
                }
            };

            let metadata_changed = match &old_entry {
                Some(old) => {
                    old.size != new_entry.size
                        || old.permissions != new_entry.permissions
                        || old.uid != new_entry.uid
                        || old.gid != new_entry.gid
                        || old.mtime != new_entry.mtime
                }
                None => true,
            };

            let metadata_only = kind == FsEventKind::MetadataChanged;

            if metadata_changed {
                let payload = format_syscheck_event(
                    ChangeType::Modified,
                    &new_entry.path,
                    old_entry.as_ref(),
                    Some(&new_entry),
                );
                if let Err(e) = db.upsert_entry(&new_entry) {
                    warn!(error = %e, path = %path_str, "DB upsert failed");
                }
                batcher.push(Event::new(
                    "fim",
                    Priority::Normal,
                    build_event_kind(
                        ChangeType::Modified,
                        metadata_only,
                        path_str.clone(),
                        payload,
                    ),
                ));
            }

            if check_sha256 && new_entry.sha256.is_none() {
                pending.push(PendingHashJob {
                    kind: ChangeType::Modified,
                    metadata_only,
                    old_entry,
                    new_entry,
                    path,
                });
            }
        }

        FsEventKind::Deleted => {
            let path_str = path.to_string_lossy().to_string();
            let old_entry = match db.get_entry(&path_str) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, path = %path_str, "DB lookup failed");
                    return pending;
                }
            };

            let payload =
                format_syscheck_event(ChangeType::Deleted, &path_str, old_entry.as_ref(), None);

            if let Err(e) = db.delete_entry(&path_str) {
                warn!(error = %e, path = %path_str, "DB delete failed");
            }

            batcher.push(Event::new(
                "fim",
                Priority::Normal,
                build_event_kind(ChangeType::Deleted, false, path_str, payload),
            ));
        }

        FsEventKind::Renamed => {
            let path_str = path.to_string_lossy().to_string();
            let old_entry = match db.get_entry(&path_str) {
                Ok(e) => e,
                Err(e) => {
                    warn!(error = %e, path = %path_str, "DB lookup failed");
                    None
                }
            };

            if let Some(ref old) = old_entry {
                let payload =
                    format_syscheck_event(ChangeType::Deleted, &path_str, Some(old), None);
                if let Err(e) = db.delete_entry(&path_str) {
                    warn!(error = %e, path = %path_str, "DB delete failed");
                }
                batcher.push(Event::new(
                    "fim",
                    Priority::Normal,
                    build_event_kind(ChangeType::Deleted, false, path_str.clone(), payload),
                ));
            }

            if path.exists() {
                if let Ok(new_entry) = collect_metadata(&path, false) {
                    if let Err(e) = db.upsert_entry(&new_entry) {
                        warn!(error = %e, path = %path_str, "DB upsert failed");
                    }
                    let payload = format_syscheck_event(
                        ChangeType::Added,
                        &new_entry.path,
                        None,
                        Some(&new_entry),
                    );
                    batcher.push(Event::new(
                        "fim",
                        Priority::Normal,
                        build_event_kind(ChangeType::Added, false, path_str, payload),
                    ));

                    if check_sha256 && new_entry.sha256.is_none() {
                        pending.push(PendingHashJob {
                            kind: ChangeType::Added,
                            metadata_only: false,
                            old_entry: None,
                            new_entry,
                            path,
                        });
                    }
                }
            }
        }
    }

    pending
}

/// Rate-limited dispatch of a single pending hash job.
async fn dispatch_hash_job(
    job: PendingHashJob,
    rate_limiter: &mut RateLimiter,
    hash_tx: &mpsc::Sender<HashResult>,
) {
    rate_limiter.acquire().await;

    let tx = hash_tx.clone();
    let PendingHashJob {
        kind,
        metadata_only,
        old_entry,
        new_entry,
        path,
    } = job;
    tokio::spawn(async move {
        let hash = hash_file_async(path).await.ok().flatten();
        let _ = tx
            .send(HashResult {
                kind,
                metadata_only,
                old_entry,
                new_entry,
                hash,
            })
            .await;
    });
}

/// Apply a completed hash result: update the DB with the now-known
/// hash and enqueue a follow-up event.
fn handle_hash_result(mut result: HashResult, db: &StateDb, batcher: &mut EventBatcher) {
    let hash = match result.hash.take() {
        Some(h) => h,
        None => return,
    };

    result.new_entry.sha256 = Some(hash);
    if let Err(e) = db.upsert_entry(&result.new_entry) {
        warn!(
            error = %e,
            path = %result.new_entry.path,
            "failed to persist hashed entry"
        );
    }

    let payload = format_syscheck_event(
        result.kind,
        &result.new_entry.path,
        result.old_entry.as_ref(),
        Some(&result.new_entry),
    );
    let path_str = result.new_entry.path.clone();
    batcher.push(Event::new(
        "fim",
        Priority::Normal,
        build_event_kind(result.kind, result.metadata_only, path_str, payload),
    ));
}

/// Async wrapper that runs the baseline scan in a blocking task and
/// publishes collected events on the event bus afterward.
async fn run_baseline_scan_task(
    db_path: Option<PathBuf>,
    directories: Vec<sda_core::config::FimDirectory>,
    bus: EventBus,
) {
    let db_path = match db_path {
        Some(p) => p,
        None => {
            warn!("baseline scan skipped: no on-disk DB path (in-memory fallback)");
            return;
        }
    };

    let result = tokio::task::spawn_blocking(move || {
        // Check idle before scanning.
        scanner::wait_for_idle(3, 60);
        scanner::run_baseline_scan(&db_path, &directories)
    })
    .await;

    match result {
        Ok(Ok((scan_result, events))) => {
            info!(
                scanned = scan_result.files_scanned,
                new = scan_result.new_files,
                modified = scan_result.modified_files,
                deleted = scan_result.deleted_files,
                "baseline scan complete"
            );
            for pending in events {
                let bus_event = Event::new("fim-scanner", Priority::Low, pending.kind);
                if let Err(e) = bus.publish_to_server(bus_event).await {
                    warn!(error = %e, "failed to publish baseline scan event");
                }
            }
        }
        Ok(Err(e)) => {
            error!(error = %e, "baseline scan failed");
        }
        Err(e) => {
            error!(error = %e, "baseline scan task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::config::{FimConfig, FimDirectory, ModulesConfig};
    use sda_core::power::PowerProfile;
    use sda_core::signal::ShutdownController;
    use std::time::Duration;
    use tempfile::TempDir;

    /// Build a minimal `AgentConfig` that watches `dir`.
    fn test_config(dir: &str) -> sda_core::config::AgentConfig {
        sda_core::config::AgentConfig {
            modules: ModulesConfig {
                fim: FimConfig {
                    enabled: true,
                    directories: vec![FimDirectory {
                        path: dir.to_string(),
                        recursive: true,
                        realtime: true,
                        check_sha256: true,
                        exclude: Vec::new(),
                    }],
                    scan_interval: 86400,
                    debounce_ms: 50,
                    max_hashes_per_sec: 1000,
                    batch_size: 1,
                    batch_timeout_ms: 50,
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_fim_module_detects_file_creation_and_publishes_event() {
        let tmp = TempDir::new().unwrap();
        // Canonicalize to resolve symlinks (macOS: /var -> /private/var).
        let canon = tmp.path().canonicalize().unwrap();
        let config = test_config(canon.to_str().unwrap());

        let (bus, mut server_rx) = EventBus::new(256, 256);
        let (controller, signal) = ShutdownController::new();
        let (_power_tx, power_rx) = sda_core::power_profile_channel(PowerProfile::Normal);

        let _handle = FimModule::start(&config, bus, signal, power_rx);

        // Wait for the watcher to register.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create a file.
        let file_path = tmp.path().join("unit_test.txt");
        std::fs::write(&file_path, "unit test content").unwrap();

        // Wait for a FileCreated event on the server channel.
        let event = tokio::time::timeout(Duration::from_secs(10), server_rx.recv())
            .await
            .expect("timed out waiting for FIM event")
            .expect("server_rx closed");

        match &event.kind {
            EventKind::FileCreated {
                path,
                syscheck_payload,
            }
            | EventKind::FileModified {
                path,
                syscheck_payload,
            }
            | EventKind::FileMetadataChanged {
                path,
                syscheck_payload,
            } => {
                // On macOS kqueue may report the directory itself instead of
                // the individual file, so accept either.
                let canon_dir = canon.to_str().unwrap();
                assert!(
                    path.contains("unit_test.txt") || path.contains(canon_dir),
                    "event path should reference watched dir or file, got: {path}"
                );
                assert!(
                    syscheck_payload.is_some(),
                    "syscheck_payload should be present"
                );
                let payload = syscheck_payload.as_ref().unwrap();
                let parsed: serde_json::Value =
                    serde_json::from_str(payload).expect("syscheck_payload should be valid JSON");
                assert_eq!(parsed["type"], "event");
                let data_path = parsed["data"]["path"].as_str().unwrap();
                assert!(
                    data_path.contains("unit_test.txt") || data_path.contains(canon_dir),
                    "payload path should reference watched dir or file, got: {data_path}"
                );
            }
            other => panic!("expected FileCreated/FileModified, got: {other:?}"),
        }

        controller.shutdown();
    }

    #[test]
    fn effective_scan_interval_stretches_on_battery() {
        let base = Duration::from_secs(3600);
        let ac = effective_scan_interval(base, PowerProfile::Normal).unwrap();
        let battery = effective_scan_interval(base, PowerProfile::BatteryActive).unwrap();
        let idle_ac = effective_scan_interval(base, PowerProfile::IdleAC).unwrap();

        assert_eq!(ac, base, "Normal should preserve configured interval");
        assert!(
            battery > ac,
            "BatteryActive should stretch the interval, got {battery:?} vs {ac:?}"
        );
        assert!(
            idle_ac < ac,
            "IdleAC should shrink the interval, got {idle_ac:?} vs {ac:?}"
        );
    }

    #[test]
    fn effective_scan_interval_pauses_on_critical_battery() {
        assert!(
            effective_scan_interval(Duration::from_secs(60), PowerProfile::CriticalBattery)
                .is_none()
        );
    }

    #[test]
    fn effective_hash_budget_scales_with_profile() {
        let base = 1000u32;
        let ac = effective_hash_budget(base, PowerProfile::Normal);
        let battery = effective_hash_budget(base, PowerProfile::BatteryActive);
        let critical = effective_hash_budget(base, PowerProfile::CriticalBattery);

        assert_eq!(ac, base);
        assert!(battery < ac && battery > 0);
        // CriticalBattery must never emit a literal 0 (that disables
        // rate limiting in RateLimiter); the sentinel is 1.
        assert_eq!(critical, 1);
    }

    #[test]
    fn effective_hash_budget_preserves_unlimited_opt_out() {
        // Callers that set max_hashes_per_sec = 0 explicitly want no
        // rate limiting at all — the profile must not magically
        // introduce one.
        assert_eq!(effective_hash_budget(0, PowerProfile::Normal), 0);
        assert_eq!(effective_hash_budget(0, PowerProfile::CriticalBattery), 0);
    }
}
