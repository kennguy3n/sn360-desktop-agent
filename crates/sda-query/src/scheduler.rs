//! Scheduled-query loop for the osquery sidecar.
//!
//! The scheduler holds a list of [`ScheduledQuery`]s and drives
//! them through an [`OsqueryClient`] at the cadence configured in
//! `modules.query.scheduled_queries[*].interval_secs`. Each
//! successful execution becomes an [`EventKind::QueryResult`] on
//! the event bus.
//!
//! Currently ships only the scheduling primitives; the actual loop
//! is wired up by [`crate::QueryModule::start`] once we have a
//! real [`OsqueryClient`].

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::client::{ClientError, OsqueryClient, QueryResultSet};

/// One scheduled query — name + SQL + cadence + per-query
/// `max_rows` cap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScheduledQuery {
    pub name: String,
    pub sql: String,
    /// How often to run this query, in seconds.
    pub interval_secs: u64,
    /// Hard cap on result rows per execution. The scheduler
    /// truncates the row vector to this length and sets
    /// [`QueryResultSet::truncated`] when it does.
    pub max_rows: usize,
}

impl ScheduledQuery {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}

/// The scheduler's per-tick decision.
#[derive(Debug, Clone, PartialEq)]
pub enum Tick {
    /// `now` is past the next scheduled run for this query —
    /// the caller should execute it.
    Run,
    /// The query is not yet due. Wait at least this long before
    /// asking again.
    Sleep(Duration),
}

/// Tracks per-query "next run" times so the supervisor can pick
/// the next query that should run without scanning every entry.
#[derive(Debug, Clone)]
pub struct Scheduler {
    /// Owned list — the executor reads SQL/name from here.
    pub queries: Vec<ScheduledQuery>,
    /// Parallel array: `next_run[i]` is the time at which
    /// `queries[i]` next becomes due. We use a parallel `Vec`
    /// rather than a `BTreeMap` because the cardinality is small
    /// (typical SME tenant schedules <20 queries) and a flat
    /// scan is faster than a tree walk for that size.
    next_run: Vec<DateTime<Utc>>,
}

impl Scheduler {
    pub fn new(queries: Vec<ScheduledQuery>, now: DateTime<Utc>) -> Self {
        let next_run = vec![now; queries.len()];
        Self { queries, next_run }
    }

    /// Decide what the supervisor should do at `now`:
    /// * `Tick::Run` if at least one query is due — the index of
    ///   the query is returned alongside it.
    /// * `Tick::Sleep(d)` if no query is due — the duration is
    ///   the time until the soonest next run.
    pub fn tick(&self, now: DateTime<Utc>) -> (Option<usize>, Tick) {
        if self.queries.is_empty() {
            // With no queries, sleep "forever". We pick a long but
            // finite duration so the caller's `tokio::time::sleep`
            // is well-defined.
            return (None, Tick::Sleep(Duration::from_secs(3600)));
        }

        let mut soonest_idx: Option<usize> = None;
        let mut soonest_run: Option<DateTime<Utc>> = None;
        for (i, run_at) in self.next_run.iter().enumerate() {
            if *run_at <= now {
                return (Some(i), Tick::Run);
            }
            if soonest_run.map(|t| *run_at < t).unwrap_or(true) {
                soonest_run = Some(*run_at);
                soonest_idx = Some(i);
            }
        }
        let next = soonest_run.expect("non-empty queries imply a next_run");
        let dur = (next - now)
            .to_std()
            .unwrap_or(Duration::from_millis(0))
            // Floor at 1 ms so the caller never busy-loops.
            .max(Duration::from_millis(1));
        let _ = soonest_idx; // Future use: hand back which query is due next.
        (None, Tick::Sleep(dur))
    }

    /// Mark `idx` as just-run, scheduling its next execution.
    pub fn record_run(&mut self, idx: usize, now: DateTime<Utc>) {
        let interval =
            chrono::Duration::from_std(self.queries[idx].interval()).unwrap_or_else(|_| {
                // Saturate at i64::MAX seconds — anything pathological
                // gets rounded to "essentially never".
                chrono::Duration::seconds(i64::MAX / 2)
            });
        self.next_run[idx] = now + interval;
    }

    /// Run one query and apply the [`ScheduledQuery::max_rows`]
    /// cap.
    pub fn execute<C: OsqueryClient>(
        &self,
        client: &C,
        idx: usize,
    ) -> Result<QueryResultSet, ClientError> {
        let q = &self.queries[idx];
        let mut rs = client.execute(&format!("schedule.{}", q.name), &q.sql)?;
        if rs.rows.len() > q.max_rows {
            rs.rows.truncate(q.max_rows);
            rs.truncated = true;
        }
        Ok(rs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::QueryRow;
    use chrono::TimeZone;
    use std::cell::RefCell;
    use std::sync::Mutex;

    fn q(name: &str, every: u64, cap: usize) -> ScheduledQuery {
        ScheduledQuery {
            name: name.into(),
            sql: format!("SELECT * FROM {name}"),
            interval_secs: every,
            max_rows: cap,
        }
    }

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 7, 8, 30, 0).unwrap()
    }

    #[test]
    fn empty_scheduler_sleeps() {
        let s = Scheduler::new(vec![], t0());
        let (idx, tick) = s.tick(t0());
        assert!(idx.is_none());
        assert!(matches!(tick, Tick::Sleep(_)));
    }

    #[test]
    fn scheduler_runs_immediately_on_first_tick() {
        let s = Scheduler::new(vec![q("a", 60, 100)], t0());
        let (idx, tick) = s.tick(t0());
        assert_eq!(idx, Some(0));
        assert_eq!(tick, Tick::Run);
    }

    #[test]
    fn scheduler_sleeps_after_recording_run() {
        let mut s = Scheduler::new(vec![q("a", 60, 100)], t0());
        s.record_run(0, t0());
        let (idx, tick) = s.tick(t0());
        assert!(idx.is_none());
        match tick {
            Tick::Sleep(d) => assert!(d <= Duration::from_secs(60)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn scheduler_runs_again_after_interval() {
        let mut s = Scheduler::new(vec![q("a", 60, 100)], t0());
        s.record_run(0, t0());
        let (idx, tick) = s.tick(t0() + chrono::Duration::seconds(60));
        assert_eq!(idx, Some(0));
        assert_eq!(tick, Tick::Run);
    }

    #[test]
    fn scheduler_picks_next_due_first() {
        // Two queries: "a" every 60 s, "b" every 30 s. After 30 s,
        // "b" should be the one returned as Run.
        let mut s = Scheduler::new(vec![q("a", 60, 100), q("b", 30, 100)], t0());
        s.record_run(0, t0());
        s.record_run(1, t0());
        let (idx, tick) = s.tick(t0() + chrono::Duration::seconds(35));
        assert_eq!(tick, Tick::Run);
        assert_eq!(idx, Some(1));
    }

    /// Stub client that returns a fixed row count regardless of
    /// SQL.
    struct StubClient {
        rows: usize,
        log: Mutex<RefCell<Vec<String>>>,
    }

    impl OsqueryClient for StubClient {
        fn execute(
            &self,
            query_id: &str,
            sql: &str,
        ) -> Result<QueryResultSet, crate::client::ClientError> {
            self.log
                .lock()
                .unwrap()
                .borrow_mut()
                .push(format!("{query_id}/{sql}"));
            let mut rows = Vec::with_capacity(self.rows);
            for i in 0..self.rows {
                let mut r = QueryRow::new();
                r.insert("idx".into(), serde_json::Value::from(i));
                rows.push(r);
            }
            Ok(QueryResultSet {
                query_id: query_id.into(),
                sql: sql.into(),
                rows,
                truncated: false,
            })
        }
    }

    #[test]
    fn execute_applies_max_rows_cap() {
        let s = Scheduler::new(vec![q("a", 60, 5)], t0());
        let stub = StubClient {
            rows: 12,
            log: Mutex::new(RefCell::new(vec![])),
        };
        let rs = s.execute(&stub, 0).unwrap();
        assert_eq!(rs.rows.len(), 5);
        assert!(rs.truncated);
    }

    #[test]
    fn execute_below_cap_is_not_truncated() {
        let s = Scheduler::new(vec![q("a", 60, 50)], t0());
        let stub = StubClient {
            rows: 3,
            log: Mutex::new(RefCell::new(vec![])),
        };
        let rs = s.execute(&stub, 0).unwrap();
        assert_eq!(rs.rows.len(), 3);
        assert!(!rs.truncated);
    }

    #[test]
    fn execute_propagates_client_errors() {
        struct FailingClient;
        impl OsqueryClient for FailingClient {
            fn execute(
                &self,
                _query_id: &str,
                _sql: &str,
            ) -> Result<QueryResultSet, crate::client::ClientError> {
                Err(crate::client::ClientError::Unavailable("nope".into()))
            }
        }
        let s = Scheduler::new(vec![q("a", 60, 5)], t0());
        let r = s.execute(&FailingClient, 0);
        assert!(matches!(r, Err(crate::client::ClientError::Unavailable(_))));
    }
}
