//! Offline detection queue.
//!
//! When the server is unreachable, finalised detection payloads are
//! buffered to a SQLite database opened in [WAL
//! mode](https://sqlite.org/wal.html) so writes don't block readers.
//! The queue is a bounded FIFO: once `capacity` entries are resident,
//! each new `enqueue()` evicts the oldest entry.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, OpenFlags};

/// Bounded, persistent, FIFO queue of detection payloads.
///
/// The underlying [`rusqlite::Connection`] is not `Sync` (it uses a
/// statement cache backed by `RefCell`), so we guard it with a
/// `std::sync::Mutex`. All operations are short SQL calls, so lock
/// contention is negligible; holding a sync lock across an `await` is
/// avoided by doing work only inside the guard.
pub struct OfflineQueue {
    conn: Mutex<Connection>,
    capacity: usize,
}

/// A single queued detection payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDetection {
    /// Monotonic identifier — strictly increasing in enqueue order.
    pub id: i64,
    /// UTC seconds-since-epoch at enqueue time.
    pub enqueued_at: i64,
    /// Raw JSON payload (the same body that would have been shipped).
    pub payload: String,
}

impl OfflineQueue {
    /// Open (or create) the queue at `path` with the given `capacity`.
    pub fn open(path: &Path, capacity: usize) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| {
            anyhow::anyhow!("failed to open offline queue at {}: {}", path.display(), e)
        })?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            capacity: capacity.max(1),
        })
    }

    /// Open an in-memory queue — used by tests only.
    pub fn in_memory(capacity: usize) -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            capacity: capacity.max(1),
        })
    }

    fn init(conn: &Connection) -> anyhow::Result<()> {
        // WAL is a no-op on in-memory DBs but free on real files.
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS detection_queue (
                 id           INTEGER PRIMARY KEY AUTOINCREMENT,
                 enqueued_at  INTEGER NOT NULL,
                 payload      TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_detection_queue_id
                 ON detection_queue(id);",
        )?;
        Ok(())
    }

    /// Push a payload onto the queue.  If the queue is at capacity,
    /// the oldest N entries are dropped before insertion.
    pub fn enqueue(&self, payload: &str) -> anyhow::Result<()> {
        self.enqueue_at(payload, now_secs())
    }

    /// Like [`enqueue`](Self::enqueue) but with an explicit timestamp.
    pub fn enqueue_at(&self, payload: &str, ts_secs: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute(
            "INSERT INTO detection_queue (enqueued_at, payload) VALUES (?1, ?2)",
            params![ts_secs, payload],
        )?;
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM detection_queue", [], |row| row.get(0))?;
        if count as usize > self.capacity {
            let to_drop = count as usize - self.capacity;
            conn.execute(
                "DELETE FROM detection_queue WHERE id IN
                     (SELECT id FROM detection_queue ORDER BY id ASC LIMIT ?1)",
                params![to_drop as i64],
            )?;
        }
        Ok(())
    }

    /// Drain up to `max` entries from the front of the queue.
    /// Returned entries are already removed from the underlying store.
    ///
    /// This is a destructive bulk read — callers that want strict FIFO
    /// in the presence of partial publish failures should prefer
    /// [`peek_batch`](Self::peek_batch) + [`ack`](Self::ack) so unsent
    /// items keep their original IDs and stay at the head of the queue.
    pub fn drain(&self, max: usize) -> anyhow::Result<Vec<QueuedDetection>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, enqueued_at, payload FROM detection_queue ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![max as i64], |row| {
                Ok(QueuedDetection {
                    id: row.get(0)?,
                    enqueued_at: row.get(1)?,
                    payload: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        if !rows.is_empty() {
            let max_id = rows.iter().map(|r| r.id).max().unwrap_or(0);
            conn.execute(
                "DELETE FROM detection_queue WHERE id <= ?1",
                params![max_id],
            )?;
        }
        Ok(rows)
    }

    /// Read up to `max` entries from the front of the queue without
    /// removing them.  Use [`ack`](Self::ack) to delete an entry once
    /// its payload has been durably handled (e.g. published to the
    /// server).  This preserves strict FIFO across partial failures:
    /// un-ack'd rows keep their original IDs and remain ahead of any
    /// newer enqueues.
    pub fn peek_batch(&self, max: usize) -> anyhow::Result<Vec<QueuedDetection>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT id, enqueued_at, payload FROM detection_queue ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![max as i64], |row| {
                Ok(QueuedDetection {
                    id: row.get(0)?,
                    enqueued_at: row.get(1)?,
                    payload: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a single entry by id after its payload has been handled.
    /// Missing ids are silently ignored so callers can ack idempotently.
    pub fn ack(&self, id: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute("DELETE FROM detection_queue WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Number of entries currently resident.
    pub fn len(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let n: i64 =
            conn.query_row("SELECT COUNT(*) FROM detection_queue", [], |row| row.get(0))?;
        Ok(n as usize)
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> anyhow::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Path this queue was opened at, for observability.  Returns an
    /// empty path for in-memory queues.
    pub fn path(&self) -> PathBuf {
        PathBuf::new()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_and_drain_fifo_order() {
        let q = OfflineQueue::in_memory(100).unwrap();
        q.enqueue("a").unwrap();
        q.enqueue("b").unwrap();
        q.enqueue("c").unwrap();
        let drained = q.drain(10).unwrap();
        let payloads: Vec<_> = drained.iter().map(|d| d.payload.as_str()).collect();
        assert_eq!(payloads, vec!["a", "b", "c"]);
        assert!(q.is_empty().unwrap());
    }

    #[test]
    fn test_drain_partial_keeps_remaining() {
        let q = OfflineQueue::in_memory(100).unwrap();
        q.enqueue("a").unwrap();
        q.enqueue("b").unwrap();
        q.enqueue("c").unwrap();
        let first = q.drain(1).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].payload, "a");
        assert_eq!(q.len().unwrap(), 2);
    }

    #[test]
    fn test_capacity_enforced_fifo_eviction() {
        let q = OfflineQueue::in_memory(2).unwrap();
        q.enqueue("a").unwrap();
        q.enqueue("b").unwrap();
        q.enqueue("c").unwrap();
        assert_eq!(q.len().unwrap(), 2);
        let drained = q.drain(10).unwrap();
        let payloads: Vec<_> = drained.iter().map(|d| d.payload.as_str()).collect();
        // Oldest ("a") was evicted; the remaining FIFO is b then c.
        assert_eq!(payloads, vec!["b", "c"]);
    }

    #[test]
    fn test_on_disk_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.db");
        {
            let q = OfflineQueue::open(&path, 10).unwrap();
            q.enqueue("persisted").unwrap();
            assert_eq!(q.len().unwrap(), 1);
        }
        let q = OfflineQueue::open(&path, 10).unwrap();
        assert_eq!(q.len().unwrap(), 1);
        let drained = q.drain(10).unwrap();
        assert_eq!(drained[0].payload, "persisted");
    }

    #[test]
    fn test_enqueue_stores_timestamp() {
        let q = OfflineQueue::in_memory(10).unwrap();
        q.enqueue_at("payload", 1_700_000_000).unwrap();
        let d = q.drain(1).unwrap();
        assert_eq!(d[0].enqueued_at, 1_700_000_000);
    }
}
