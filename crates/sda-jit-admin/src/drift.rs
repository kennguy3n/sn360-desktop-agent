//! JIT-admin drift detection.
//!
//! Compares the OS-level admin/root group membership returned by
//! [`AdminManager::list_admins`] against the active grants in the
//! local ledger ([`GrantStore::records`]). Discrepancies surface as
//! [`Drift`] entries; the supervisor renders each one as a
//! [`FindingKind::AdminDrift`] payload on the agent event bus and
//! emits a paired [`EvidenceRecord`] per
//! `docs/device-control.md` § 7 (Just-in-Time admin).
//!
//! Two failure modes are reported:
//!
//! 1. [`DriftKind::UntrackedAdmin`] — an account holds OS-level admin
//!    rights but no active JIT grant tracks it. Either the account
//!    was elevated outside SDA (privilege escalation) or the agent's
//!    ledger lost the corresponding entry.
//! 2. [`DriftKind::MissingPrivilege`] — a tracked grant exists in
//!    `GrantState::Granted`, but the user does not appear in the
//!    OS-level admin list. The grant is still considered active by
//!    the agent but the OS-level privilege has been revoked
//!    externally (e.g. an operator manually removed the user from
//!    `sudo` while the grant timer was still running).
//!
//! Allow-listing is supported via [`DriftDetector::allow_user`]: the
//! agent's own service accounts (`root`, the device owner, etc.) are
//! never flagged as drift even though they always show up in
//! `list_admins()`.
//!
//! The detector is a pure-logic helper — it does not own a tokio
//! task. The `Supervisor` in [`crate::module`] drives it on a
//! configurable interval inside its `tokio::select!` loop, the same
//! way it already drives [`crate::watchdog::RevocationWatchdog`].

use std::collections::HashSet;

use sda_pal::admin_manager::{AdminAccount, AdminError, AdminManager};
use serde::{Deserialize, Serialize};

use crate::grant::{GrantRecord, GrantState};

/// Why a drift entry was surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// OS-level admin without a tracked JIT grant — possible
    /// privilege escalation.
    UntrackedAdmin,
    /// Tracked grant whose user is no longer in the OS-level admin
    /// group — privilege was externally removed.
    MissingPrivilege,
}

impl DriftKind {
    /// Lower-snake-case label suitable for the `drift_kind` evidence
    /// field rendered into [`crate::evidence::DriftEvidence`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UntrackedAdmin => "untracked_admin",
            Self::MissingPrivilege => "missing_privilege",
        }
    }
}

/// One drift observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drift {
    /// Kind of discrepancy.
    pub kind: DriftKind,
    /// User the discrepancy is about (lowercased login).
    pub user: String,
    /// Optional group label observed on the OS side (`sudo`,
    /// `wheel`, `Administrators`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Source label observed on the OS side (`local`, `domain`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Tracked grant id, when [`DriftKind::MissingPrivilege`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

/// Errors produced by [`DriftDetector::scan`].
#[derive(Debug, thiserror::Error)]
pub enum DriftError {
    /// The underlying [`AdminManager::list_admins`] call failed.
    #[error("list_admins failed: {0}")]
    ListAdmins(#[from] AdminError),
}

/// Pure-logic drift detector. Owns no async machinery; the
/// supervisor drives [`DriftDetector::scan`] on its watchdog cadence.
#[derive(Debug, Default, Clone)]
pub struct DriftDetector {
    /// Lower-cased usernames that are *expected* to hold admin
    /// rights without a corresponding JIT grant. Defaults include
    /// `root`, `Administrator`, and `LocalSystem`; callers may
    /// extend it for the agent's own service account, device owner,
    /// etc.
    allow: HashSet<String>,
}

impl DriftDetector {
    /// Build a detector with the canonical baseline allow-list:
    ///
    /// * `root` — the POSIX super-user is always present and is not
    ///   provisioned via JIT grants.
    /// * `administrator` — the Windows built-in admin account.
    /// * `localsystem` — the Windows `NT AUTHORITY\SYSTEM` principal.
    pub fn new() -> Self {
        let mut allow = HashSet::new();
        for s in ["root", "administrator", "localsystem"] {
            allow.insert(s.to_string());
        }
        Self { allow }
    }

    /// Add `user` to the allow-list (case-insensitive).
    pub fn allow_user(mut self, user: impl Into<String>) -> Self {
        self.allow.insert(user.into().to_lowercase());
        self
    }

    /// `true` iff `user` is on the allow-list.
    pub fn is_allowed(&self, user: &str) -> bool {
        self.allow.contains(&user.to_lowercase())
    }

    /// Run one drift comparison. The caller passes the live
    /// [`AdminManager`] and the current ledger snapshot; the detector
    /// returns one [`Drift`] entry per discrepancy.
    ///
    /// Wraps [`Self::compare`] so callers don't have to know how to
    /// invoke `list_admins()` themselves; tests usually call
    /// [`Self::compare`] directly with a hand-crafted vector.
    pub fn scan(
        &self,
        admin: &dyn AdminManager,
        ledger: &[GrantRecord],
    ) -> Result<Vec<Drift>, DriftError> {
        let admins = admin.list_admins()?;
        Ok(self.compare(&admins, ledger))
    }

    /// Pure-logic drift compare — the test seam.
    ///
    /// `admins` is the current OS-level admin list, `ledger` is the
    /// JIT-admin grant ledger. The result is a fresh `Vec` of drift
    /// entries; the caller decides how to surface them (findings,
    /// evidence records, force-revoke, …).
    pub fn compare(&self, admins: &[AdminAccount], ledger: &[GrantRecord]) -> Vec<Drift> {
        let admin_set: HashSet<String> = admins.iter().map(|a| a.username.to_lowercase()).collect();
        let tracked: HashSet<String> = ledger
            .iter()
            .filter(|r| r.state == GrantState::Granted)
            .map(|r| r.user.username.to_lowercase())
            .collect();

        let mut out: Vec<Drift> = Vec::new();

        // 1. Admins without a tracking grant.
        for admin in admins {
            let lower = admin.username.to_lowercase();
            if self.is_allowed(&lower) {
                continue;
            }
            if tracked.contains(&lower) {
                continue;
            }
            out.push(Drift {
                kind: DriftKind::UntrackedAdmin,
                user: admin.username.clone(),
                group: admin.group.clone(),
                source: Some(admin.source.clone()),
                grant_id: None,
            });
        }

        // 2. Granted records whose user is no longer admin on the
        //    box (privilege removed externally).
        for record in ledger {
            if record.state != GrantState::Granted {
                continue;
            }
            let lower = record.user.username.to_lowercase();
            if admin_set.contains(&lower) {
                continue;
            }
            out.push(Drift {
                kind: DriftKind::MissingPrivilege,
                user: record.user.username.clone(),
                group: None,
                source: None,
                grant_id: Some(record.id.clone()),
            });
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sda_pal::admin_manager::{AdminError, AdminManager, GrantHandle, UserRef as PalUserRef};
    use std::sync::Mutex;

    /// Test-only [`AdminManager`] that returns a canned admin list.
    #[derive(Debug, Default)]
    struct CannedAdmins {
        admins: Mutex<Vec<AdminAccount>>,
    }

    impl CannedAdmins {
        fn with(admins: Vec<AdminAccount>) -> Self {
            Self {
                admins: Mutex::new(admins),
            }
        }
    }

    impl AdminManager for CannedAdmins {
        fn list_admins(&self) -> Result<Vec<AdminAccount>, AdminError> {
            Ok(self.admins.lock().unwrap().clone())
        }
        fn grant_admin(
            &self,
            _user: &PalUserRef,
            _until: chrono::DateTime<Utc>,
        ) -> Result<GrantHandle, AdminError> {
            Err(AdminError::NotImplemented)
        }
        fn revoke_admin(&self, _handle: &GrantHandle) -> Result<(), AdminError> {
            Err(AdminError::NotImplemented)
        }
        fn observed_grants(&self) -> Result<Vec<GrantHandle>, AdminError> {
            Ok(Vec::new())
        }
    }

    fn admin(name: &str, group: &str) -> AdminAccount {
        AdminAccount {
            username: name.into(),
            source: "local".into(),
            since: None,
            group: Some(group.into()),
        }
    }

    fn user(name: &str) -> PalUserRef {
        PalUserRef {
            username: name.into(),
            domain: None,
        }
    }

    fn granted(id: &str, name: &str) -> GrantRecord {
        let now = Utc::now();
        let mut r = GrantRecord::new_requested(
            id,
            "ops",
            user(name),
            now + chrono::Duration::hours(1),
            now,
        );
        r.state = GrantState::Granted;
        r
    }

    #[test]
    fn root_is_allow_listed_by_default() {
        let det = DriftDetector::new();
        let drifts = det.compare(&[admin("root", "wheel")], &[]);
        assert!(drifts.is_empty(), "root must be allow-listed");
    }

    #[test]
    fn untracked_admin_yields_drift() {
        let det = DriftDetector::new();
        let drifts = det.compare(&[admin("alice", "sudo")], &[]);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].kind, DriftKind::UntrackedAdmin);
        assert_eq!(drifts[0].user, "alice");
        assert_eq!(drifts[0].group.as_deref(), Some("sudo"));
        assert_eq!(drifts[0].source.as_deref(), Some("local"));
    }

    #[test]
    fn tracked_admin_does_not_drift() {
        let det = DriftDetector::new();
        let drifts = det.compare(&[admin("alice", "sudo")], &[granted("g-1", "alice")]);
        assert!(drifts.is_empty());
    }

    #[test]
    fn missing_privilege_yields_drift() {
        let det = DriftDetector::new();
        // Tracked grant for alice but no OS-level admin entry.
        let drifts = det.compare(&[admin("root", "wheel")], &[granted("g-1", "alice")]);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].kind, DriftKind::MissingPrivilege);
        assert_eq!(drifts[0].user, "alice");
        assert_eq!(drifts[0].grant_id.as_deref(), Some("g-1"));
    }

    #[test]
    fn allow_user_is_case_insensitive() {
        let det = DriftDetector::new().allow_user("Bob");
        assert!(det.is_allowed("bob"));
        assert!(det.is_allowed("BOB"));
        let drifts = det.compare(&[admin("BOB", "Administrators")], &[]);
        assert!(drifts.is_empty());
    }

    #[test]
    fn admin_match_is_case_insensitive() {
        let det = DriftDetector::new();
        // OS reports "Alice", grant tracks "alice" — must NOT drift.
        let drifts = det.compare(&[admin("Alice", "sudo")], &[granted("g-1", "alice")]);
        assert!(drifts.is_empty());
    }

    #[test]
    fn requested_or_approved_grants_do_not_count_as_tracking() {
        let det = DriftDetector::new();
        // alice is admin on the OS but the grant for her is still
        // Approved (not Granted) — that means the OS-level privilege
        // landed before the agent finished its grant transition,
        // which is a real drift case we want surfaced.
        let mut g = granted("g-1", "alice");
        g.state = GrantState::Approved;
        let drifts = det.compare(&[admin("alice", "sudo")], &[g]);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].kind, DriftKind::UntrackedAdmin);
    }

    #[test]
    fn terminal_grants_do_not_count_as_tracking() {
        let det = DriftDetector::new();
        // Revoked grant — alice should not be admin on the OS any
        // more; if she still is, that's drift.
        let mut g = granted("g-1", "alice");
        g.state = GrantState::Revoked;
        let drifts = det.compare(&[admin("alice", "sudo")], &[g]);
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].kind, DriftKind::UntrackedAdmin);
    }

    #[test]
    fn scan_calls_list_admins() {
        let canned = CannedAdmins::with(vec![admin("eve", "sudo")]);
        let det = DriftDetector::new();
        let drifts = det.scan(&canned, &[]).unwrap();
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].user, "eve");
    }

    #[test]
    fn drift_kind_round_trips_through_serde() {
        for k in [DriftKind::UntrackedAdmin, DriftKind::MissingPrivilege] {
            let json = serde_json::to_string(&k).unwrap();
            let back: DriftKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
            assert!(json.contains(k.as_str()));
        }
    }
}
