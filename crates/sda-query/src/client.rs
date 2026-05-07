//! Minimal client for the osquery extension socket.
//!
//! Phase 1 ships a *placeholder* client that knows the wire format
//! but does not actually open the socket — the executor lands in
//! Phase 2 alongside JIT admin and software-management. The shape
//! is fully defined here so unit tests for [`crate::scheduler`] can
//! mock it out without touching the real Thrift transport.

use serde::{Deserialize, Serialize};

/// One row of an osquery query result.
///
/// osquery returns each row as a JSON object whose keys are the
/// SELECT-list column names and whose values are stringified cell
/// contents. We model that exactly to avoid lossy conversions.
pub type QueryRow = serde_json::Map<String, serde_json::Value>;

/// Result of executing one ad-hoc or scheduled query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryResultSet {
    /// The query identifier (`schedule.<name>` or a UUIDv7 for
    /// ad-hoc).
    pub query_id: String,
    /// SQL text actually executed by osquery.
    pub sql: String,
    /// One row per matching record. Truncated to the configured
    /// `max_rows` cap by the scheduler.
    pub rows: Vec<QueryRow>,
    /// `true` iff `rows` was clipped against `max_rows`.
    pub truncated: bool,
}

/// Errors returned by [`OsqueryClient`].
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The osquery extension socket could not be reached.
    ///
    /// Phase 1 callers map this onto a warning + `Skipped`
    /// scheduling decision so a missing osquery binary doesn't
    /// crash the agent.
    #[error("osquery extension socket unavailable: {0}")]
    Unavailable(String),
    /// The osquery server returned a non-success status.
    #[error("osquery query failed: {0}")]
    QueryFailed(String),
    /// Catch-all for socket / serde errors.
    #[error("osquery client I/O: {0}")]
    Io(String),
}

/// Trait abstraction for the Thrift-over-Unix-socket osquery
/// extension API.
///
/// We keep this as a trait so the scheduler can be unit-tested
/// against a fake without spawning a real osquery process.
pub trait OsqueryClient: Send + Sync {
    /// Execute one SQL query and return the rows.
    fn execute(&self, query_id: &str, sql: &str) -> Result<QueryResultSet, ClientError>;
}

/// Phase 1 placeholder: always returns
/// [`ClientError::Unavailable`].
///
/// Replaced in Phase 2 by a real `osquery_thrift::Client` wired up
/// to the spawned sidecar process. The scheduler treats the
/// `Unavailable` error as a soft failure and emits a Low-priority
/// warning event rather than crashing the agent.
#[derive(Debug, Default)]
pub struct UnavailableClient {
    pub reason: String,
}

impl OsqueryClient for UnavailableClient {
    fn execute(&self, _query_id: &str, _sql: &str) -> Result<QueryResultSet, ClientError> {
        Err(ClientError::Unavailable(if self.reason.is_empty() {
            "osquery sidecar not yet wired (Phase 2)".into()
        } else {
            self.reason.clone()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unavailable_client_returns_unavailable_error() {
        let c = UnavailableClient::default();
        let err = c.execute("q1", "SELECT 1").unwrap_err();
        assert!(matches!(err, ClientError::Unavailable(_)));
    }

    #[test]
    fn unavailable_client_reports_custom_reason() {
        let c = UnavailableClient {
            reason: "no binary at /usr/bin/osqueryd".into(),
        };
        let err = c.execute("q1", "SELECT 1").unwrap_err();
        match err {
            ClientError::Unavailable(s) => assert!(s.contains("no binary")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn query_result_set_round_trips() {
        let mut row = QueryRow::new();
        row.insert("user".into(), json!("alice"));
        row.insert("uid".into(), json!("1000"));
        let r = QueryResultSet {
            query_id: "schedule.users".into(),
            sql: "SELECT * FROM users".into(),
            rows: vec![row],
            truncated: false,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: QueryResultSet = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn query_result_set_rejects_unknown_field() {
        let raw = r#"{
            "query_id": "q",
            "sql": "x",
            "rows": [],
            "truncated": false,
            "extra": 1
        }"#;
        assert!(serde_json::from_str::<QueryResultSet>(raw).is_err());
    }
}
