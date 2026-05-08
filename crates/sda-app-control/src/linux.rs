//! Linux app-control backend: clean-room dm-verity-aware binary
//! enforcement (Task 4.8).
//!
//! The Linux backend is intentionally minimalist. The agent:
//!
//! * **Writes policy to disk** under
//!   `<policy_dir>/policy.rules`. The format is a deterministic,
//!   line-oriented `kind value action reason` tabular layout so
//!   downstream consumers (a future seccomp/eBPF rules-loader,
//!   `auditd` filters, or operator review) can diff successive
//!   versions trivially.
//! * **Records every observation** in
//!   `<policy_dir>/decisions.log` in monitor mode. Each line is
//!   newline-delimited JSON containing the subject, the matched
//!   rule (if any), and a wall-clock timestamp.
//! * **Surfaces dm-verity state** through
//!   [`parse_dm_verity_status`]. Monitor mode logs the verity
//!   status alongside decisions so out-of-tree filesystem mutations
//!   (a key bypass vector on Linux) are visible to the
//!   control-plane.
//!
//! The actual seccomp/eBPF kernel integration is out of scope for
//! Phase 4 — it requires CAP_BPF, a supervisor process running as
//! root, and per-distro hardening that lives in the agent's
//! installer. Phase 4 ships the policy + decision substrate that
//! the kernel-side enforcement code will consume in a later phase.
//! This is consistent with the Santa-on-macOS pattern: the agent
//! pushes rules into the trusted backend; the trusted backend
//! enforces.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use sda_pal::app_control::{
    AppControlError, AppControlMode, AppControlPolicyPayload, AppControlProvider, AppControlRule,
};

/// Default policy directory used by [`LinuxAppControlProvider::default_dir`].
pub const DEFAULT_POLICY_DIR: &str = "/var/lib/sn360-desktop-agent/app-control";

/// File name (relative to the policy dir) the rendered policy is
/// written to.
pub const POLICY_FILE_NAME: &str = "policy.rules";

/// File name (relative to the policy dir) used for monitor-mode
/// decision logs.
pub const DECISIONS_LOG_NAME: &str = "decisions.log";

/// Header line written at the top of the rendered policy file.
const POLICY_FILE_HEADER: &str =
    "# sn360-desktop-agent app-control policy. Format: kind\tvalue\taction\treason";

/// Snapshot of `veritysetup status <device>` output.
///
/// The agent does not interpret missing fields as a hard error —
/// dm-verity may legitimately be inactive on a host that has not
/// been migrated to a verified-boot stack yet. Operators see the
/// state surfaced on the evidence record and decide policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmVerityState {
    pub device: String,
    pub status: DmVerityStatus,
    pub root_hash: Option<String>,
    pub data_device: Option<String>,
    pub hash_device: Option<String>,
}

/// Coarse dm-verity status the agent emits to the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmVerityStatus {
    /// `veritysetup status` reported `verified` — the trusted
    /// filesystem mapping is active.
    Verified,
    /// `veritysetup status` ran but the mapping is inactive.
    Inactive,
    /// `veritysetup status` is unavailable (binary missing, no
    /// mapping for this device, etc.).
    Unknown,
}

impl DmVerityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DmVerityStatus::Verified => "verified",
            DmVerityStatus::Inactive => "inactive",
            DmVerityStatus::Unknown => "unknown",
        }
    }
}

/// Parse the textual output of `veritysetup status <device>` into a
/// [`DmVerityState`].
///
/// `veritysetup` writes a stanza like:
///
/// ```text
/// /dev/mapper/root is active and is in use.
///   type:        VERITY
///   status:      verified
///   hash type:   1
///   data device: /dev/sda3
///   hash device: /dev/sda4
///   root hash:   1a2b3c...
/// ```
///
/// We parse the `<key>: <value>` lines and collapse case so
/// `Verified` / `verified` both map to the same enum.
pub fn parse_dm_verity_status(device: &str, output: &str) -> DmVerityState {
    let mut fields: HashMap<&str, String> = HashMap::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once(':') {
            fields.insert(k.trim(), v.trim().to_string());
        }
    }
    let status = match fields
        .get("status")
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("verified") => DmVerityStatus::Verified,
        Some(_) => DmVerityStatus::Inactive,
        None => DmVerityStatus::Unknown,
    };
    DmVerityState {
        device: device.to_string(),
        status,
        root_hash: fields.get("root hash").cloned(),
        data_device: fields.get("data device").cloned(),
        hash_device: fields.get("hash device").cloned(),
    }
}

/// One subject kind the Linux backend understands. Mirrors the
/// canonical subjects used elsewhere; a subject with no recognised
/// prefix is recorded verbatim and tagged `raw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxSubjectKind {
    Sha256,
    Path,
    XattrUserSecurity,
    PackageId,
    Raw,
}

impl LinuxSubjectKind {
    fn from_prefix(prefix: &str) -> Self {
        match prefix.trim() {
            "sha256" => LinuxSubjectKind::Sha256,
            "path" => LinuxSubjectKind::Path,
            "xattr" => LinuxSubjectKind::XattrUserSecurity,
            "package" | "pkg" => LinuxSubjectKind::PackageId,
            _ => LinuxSubjectKind::Raw,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LinuxSubjectKind::Sha256 => "sha256",
            LinuxSubjectKind::Path => "path",
            LinuxSubjectKind::XattrUserSecurity => "xattr",
            LinuxSubjectKind::PackageId => "package",
            LinuxSubjectKind::Raw => "raw",
        }
    }
}

/// One rule normalised for the Linux on-disk policy file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPolicyEntry {
    pub kind: LinuxSubjectKind,
    pub value: String,
    pub allow: bool,
    pub reason: String,
}

fn translate_rule(r: &AppControlRule) -> LinuxPolicyEntry {
    let (kind, value) = match r.subject.split_once(':') {
        Some((p, v)) => (LinuxSubjectKind::from_prefix(p), v.to_string()),
        None => (LinuxSubjectKind::Sha256, r.subject.clone()),
    };
    LinuxPolicyEntry {
        kind,
        value,
        allow: r.allow,
        reason: r.reason.clone(),
    }
}

/// Translated, ready-to-render Linux policy artefact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPolicyArtifact {
    pub version: u64,
    pub mode: AppControlMode,
    pub issued_at: DateTime<Utc>,
    pub entries: Vec<LinuxPolicyEntry>,
}

/// Build a [`LinuxPolicyArtifact`] from a verified payload.
pub fn build_policy_artifact(payload: &AppControlPolicyPayload) -> LinuxPolicyArtifact {
    LinuxPolicyArtifact {
        version: payload.version,
        mode: payload.target_mode,
        issued_at: payload.issued_at,
        entries: payload.rules.iter().map(translate_rule).collect(),
    }
}

fn escape_field(s: &str) -> String {
    s.replace(['\t', '\n'], " ")
}

/// Render the policy artefact to the on-disk `kind\tvalue\taction\treason`
/// format. The leading comment lines record version, mode, and
/// `issued_at` so consumers can audit which signed bundle produced
/// the file without having to walk the evidence chain.
pub fn render_policy_file(artifact: &LinuxPolicyArtifact) -> String {
    let mut out = String::new();
    out.push_str(POLICY_FILE_HEADER);
    out.push('\n');
    out.push_str(&format!("# version: {}\n", artifact.version));
    out.push_str(&format!("# mode: {}\n", artifact.mode.as_str()));
    out.push_str(&format!(
        "# issued_at: {}\n",
        artifact.issued_at.to_rfc3339()
    ));
    for e in &artifact.entries {
        let action = if e.allow { "allow" } else { "deny" };
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            e.kind.as_str(),
            escape_field(&e.value),
            action,
            escape_field(&e.reason),
        ));
    }
    out
}

/// One observation logged by the Linux backend in monitor mode.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinuxDecisionRecord {
    pub subject: String,
    pub matched_allow: Option<bool>,
    pub matched_kind: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub policy_version: u64,
    pub verity_status: String,
}

/// Render a decision record as a single newline-delimited JSON line
/// suitable for appending to `decisions.log`.
pub fn render_decision_line(record: &LinuxDecisionRecord) -> String {
    serde_json::to_string(record).unwrap_or_default() + "\n"
}

/// Match a subject against the artefact, returning the matched
/// rule (if any). The lookup is O(rules) — fine because policy
/// bundles are small (PROPOSAL.md § 9.6 caps them at 10k rules).
pub fn match_subject<'a>(
    artifact: &'a LinuxPolicyArtifact,
    subject: &str,
) -> Option<&'a LinuxPolicyEntry> {
    let translated = match subject.split_once(':') {
        Some((p, v)) => (LinuxSubjectKind::from_prefix(p), v),
        None => (LinuxSubjectKind::Sha256, subject),
    };
    artifact
        .entries
        .iter()
        .find(|e| e.kind == translated.0 && e.value == translated.1)
}

/// Cross-platform Linux app-control provider.
///
/// On Linux it persists the policy file under `policy_dir` and
/// records monitor-mode decisions to `decisions.log`. On every
/// other host it keeps the artefact in memory so cross-platform CI
/// can exercise the full translation path.
pub struct LinuxAppControlProvider {
    policy_dir: PathBuf,
    last_applied: Mutex<Option<LinuxPolicyArtifact>>,
    last_verity: Mutex<Option<DmVerityState>>,
}

impl std::fmt::Debug for LinuxAppControlProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxAppControlProvider")
            .field("policy_dir", &self.policy_dir)
            .finish()
    }
}

impl LinuxAppControlProvider {
    /// Build a provider rooted at the given policy directory.
    pub fn new(policy_dir: PathBuf) -> Self {
        Self {
            policy_dir,
            last_applied: Mutex::new(None),
            last_verity: Mutex::new(None),
        }
    }

    /// Build a provider rooted at the platform-default
    /// [`DEFAULT_POLICY_DIR`].
    pub fn default_dir() -> Self {
        Self::new(PathBuf::from(DEFAULT_POLICY_DIR))
    }

    /// Read-only snapshot of the most-recently-applied artefact.
    pub fn last_applied(&self) -> Option<LinuxPolicyArtifact> {
        self.last_applied.lock().ok().and_then(|g| g.clone())
    }

    /// Update the recorded dm-verity state. The supervisor is
    /// expected to call this periodically with the parsed output of
    /// `veritysetup status`.
    pub fn record_dm_verity(&self, state: DmVerityState) {
        if let Ok(mut g) = self.last_verity.lock() {
            *g = Some(state);
        }
    }

    /// Read-only snapshot of the most-recently-recorded dm-verity
    /// state.
    pub fn dm_verity(&self) -> Option<DmVerityState> {
        self.last_verity.lock().ok().and_then(|g| g.clone())
    }

    /// Match a subject against the active policy, render a
    /// [`LinuxDecisionRecord`], optionally append it to
    /// `decisions.log` (Linux only), and return the record.
    pub fn observe(&self, subject: &str) -> Option<LinuxDecisionRecord> {
        let artifact = self.last_applied.lock().ok().and_then(|g| g.clone())?;
        let matched = match_subject(&artifact, subject);
        let record = LinuxDecisionRecord {
            subject: subject.to_string(),
            matched_allow: matched.map(|m| m.allow),
            matched_kind: matched.map(|m| m.kind.as_str().to_string()),
            observed_at: Utc::now(),
            policy_version: artifact.version,
            verity_status: self
                .last_verity
                .lock()
                .ok()
                .and_then(|g| g.as_ref().map(|s| s.status.as_str().to_string()))
                .unwrap_or_else(|| DmVerityStatus::Unknown.as_str().to_string()),
        };
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            if let Ok(()) = std::fs::create_dir_all(&self.policy_dir) {
                let log_path = self.policy_dir.join(DECISIONS_LOG_NAME);
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                {
                    let _ = f.write_all(render_decision_line(&record).as_bytes());
                }
            }
        }
        Some(record)
    }
}

impl AppControlProvider for LinuxAppControlProvider {
    fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
        Ok(self
            .last_applied
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|a| a.mode))
            .unwrap_or(AppControlMode::Disabled))
    }

    fn apply_verified_policy(
        &self,
        payload: &AppControlPolicyPayload,
    ) -> Result<(), AppControlError> {
        let artifact = build_policy_artifact(payload);
        let rendered = render_policy_file(&artifact);

        #[cfg(target_os = "linux")]
        {
            std::fs::create_dir_all(&self.policy_dir)
                .map_err(|e| AppControlError::Backend(format!("create policy dir: {e}")))?;
            let path = self.policy_dir.join(POLICY_FILE_NAME);
            std::fs::write(&path, rendered.as_bytes())
                .map_err(|e| AppControlError::Backend(format!("write policy file: {e}")))?;
        }
        // Always retain the rendered artefact in memory so tests on
        // non-Linux hosts can assert against it.
        let _ = rendered;

        if let Ok(mut g) = self.last_applied.lock() {
            *g = Some(artifact);
        }
        Ok(())
    }
}

/// Helper for constructing a path inside the policy dir. Useful
/// for tests + for the supervisor to resolve the decisions log
/// without having to know the exact filename layout.
pub fn policy_file_path(policy_dir: &Path) -> PathBuf {
    policy_dir.join(POLICY_FILE_NAME)
}

/// Mirror of [`policy_file_path`] for the decisions log.
pub fn decisions_log_path(policy_dir: &Path) -> PathBuf {
    policy_dir.join(DECISIONS_LOG_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn payload() -> AppControlPolicyPayload {
        AppControlPolicyPayload {
            version: 4,
            issued_at: Utc.with_ymd_and_hms(2026, 5, 8, 10, 0, 0).unwrap(),
            target_mode: AppControlMode::Monitor,
            rules: vec![
                AppControlRule {
                    subject: "sha256:cafebabe".into(),
                    allow: true,
                    reason: "trusted".into(),
                },
                AppControlRule {
                    subject: "path:/usr/bin/curl".into(),
                    allow: true,
                    reason: "system curl".into(),
                },
                AppControlRule {
                    subject: "package:nmap".into(),
                    allow: false,
                    reason: "blocked tool".into(),
                },
                AppControlRule {
                    subject: "weird:thing".into(),
                    allow: true,
                    reason: "raw subject".into(),
                },
            ],
        }
    }

    #[test]
    fn parse_dm_verity_status_recognises_verified() {
        let out = "/dev/mapper/root is active and is in use.\n\
                   type:    VERITY\nstatus: verified\nroot hash: deadbeef\ndata device: /dev/sda3\n";
        let s = parse_dm_verity_status("/dev/mapper/root", out);
        assert_eq!(s.status, DmVerityStatus::Verified);
        assert_eq!(s.root_hash.as_deref(), Some("deadbeef"));
        assert_eq!(s.data_device.as_deref(), Some("/dev/sda3"));
    }

    #[test]
    fn parse_dm_verity_status_recognises_inactive() {
        let out = "/dev/mapper/root is active and is in use.\nstatus: corrupted\n";
        let s = parse_dm_verity_status("/dev/mapper/root", out);
        assert_eq!(s.status, DmVerityStatus::Inactive);
    }

    #[test]
    fn parse_dm_verity_status_recognises_unknown_when_status_missing() {
        let out = "/dev/mapper/root inactive\n";
        let s = parse_dm_verity_status("/dev/mapper/root", out);
        assert_eq!(s.status, DmVerityStatus::Unknown);
    }

    #[test]
    fn translate_rule_routes_known_kinds() {
        let r = AppControlRule {
            subject: "path:/bin/sh".into(),
            allow: true,
            reason: "shell".into(),
        };
        let e = translate_rule(&r);
        assert_eq!(e.kind, LinuxSubjectKind::Path);
        assert_eq!(e.value, "/bin/sh");
        assert!(e.allow);
    }

    #[test]
    fn translate_rule_falls_back_to_raw() {
        let r = AppControlRule {
            subject: "weird:thing".into(),
            allow: true,
            reason: String::new(),
        };
        let e = translate_rule(&r);
        assert_eq!(e.kind, LinuxSubjectKind::Raw);
        assert_eq!(e.value, "thing");
    }

    #[test]
    fn build_policy_artifact_translates_all_rules() {
        let p = payload();
        let a = build_policy_artifact(&p);
        assert_eq!(a.version, 4);
        assert_eq!(a.mode, AppControlMode::Monitor);
        assert_eq!(a.entries.len(), 4);
    }

    #[test]
    fn render_policy_file_emits_header_and_rows() {
        let a = build_policy_artifact(&payload());
        let body = render_policy_file(&a);
        assert!(body.starts_with(POLICY_FILE_HEADER));
        assert!(body.contains("# version: 4"));
        assert!(body.contains("# mode: monitor"));
        assert!(body.contains("sha256\tcafebabe\tallow\ttrusted"));
        assert!(body.contains("package\tnmap\tdeny\tblocked tool"));
    }

    #[test]
    fn render_policy_file_strips_tabs_in_fields() {
        let mut p = payload();
        p.rules.push(AppControlRule {
            subject: "path:/tmp/with\ttab".into(),
            allow: true,
            reason: "weird\tname".into(),
        });
        let body = render_policy_file(&build_policy_artifact(&p));
        for line in body.lines().filter(|l| !l.starts_with('#')) {
            assert_eq!(line.matches('\t').count(), 3, "row was: {line}");
        }
    }

    #[test]
    fn match_subject_finds_known_rule() {
        let a = build_policy_artifact(&payload());
        let m = match_subject(&a, "path:/usr/bin/curl").expect("match");
        assert_eq!(m.kind, LinuxSubjectKind::Path);
        assert!(m.allow);
    }

    #[test]
    fn match_subject_returns_none_for_missing() {
        let a = build_policy_artifact(&payload());
        assert!(match_subject(&a, "path:/usr/bin/nope").is_none());
    }

    #[test]
    fn render_decision_line_is_newline_delimited_json() {
        let r = LinuxDecisionRecord {
            subject: "sha256:abc".into(),
            matched_allow: Some(true),
            matched_kind: Some("sha256".into()),
            observed_at: Utc.with_ymd_and_hms(2026, 5, 8, 10, 0, 0).unwrap(),
            policy_version: 1,
            verity_status: "verified".into(),
        };
        let line = render_decision_line(&r);
        assert!(line.ends_with('\n'));
        let trimmed = line.trim_end();
        let parsed: LinuxDecisionRecord = serde_json::from_str(trimmed).expect("parse");
        assert_eq!(parsed.subject, "sha256:abc");
        assert_eq!(parsed.matched_allow, Some(true));
    }

    #[test]
    fn provider_records_artifact_on_apply() {
        let dir = std::env::temp_dir().join("sda-linux-test");
        let provider = LinuxAppControlProvider::new(dir);
        provider
            .apply_verified_policy(&payload())
            .expect("apply ok");
        let artefact = provider.last_applied().expect("artefact");
        assert_eq!(artefact.version, 4);
        assert_eq!(artefact.entries.len(), 4);
    }

    #[test]
    fn provider_observe_returns_match_when_subject_known() {
        let dir = std::env::temp_dir().join("sda-linux-test");
        let provider = LinuxAppControlProvider::new(dir);
        provider
            .apply_verified_policy(&payload())
            .expect("apply ok");
        let r = provider.observe("path:/usr/bin/curl").expect("observation");
        assert_eq!(r.matched_allow, Some(true));
        assert_eq!(r.matched_kind.as_deref(), Some("path"));
        assert_eq!(r.policy_version, 4);
    }

    #[test]
    fn provider_observe_returns_no_match_when_subject_unknown() {
        let dir = std::env::temp_dir().join("sda-linux-test");
        let provider = LinuxAppControlProvider::new(dir);
        provider
            .apply_verified_policy(&payload())
            .expect("apply ok");
        let r = provider.observe("sha256:zzz").expect("observation");
        assert!(r.matched_allow.is_none());
        assert!(r.matched_kind.is_none());
    }

    #[test]
    fn provider_observe_records_dm_verity_status() {
        let dir = std::env::temp_dir().join("sda-linux-test");
        let provider = LinuxAppControlProvider::new(dir);
        provider
            .apply_verified_policy(&payload())
            .expect("apply ok");
        provider.record_dm_verity(DmVerityState {
            device: "/dev/mapper/root".into(),
            status: DmVerityStatus::Verified,
            root_hash: Some("deadbeef".into()),
            data_device: None,
            hash_device: None,
        });
        let r = provider.observe("sha256:cafebabe").expect("observation");
        assert_eq!(r.verity_status, "verified");
    }

    #[test]
    fn provider_current_mode_starts_disabled() {
        let dir = std::env::temp_dir().join("sda-linux-test");
        let provider = LinuxAppControlProvider::new(dir);
        assert_eq!(provider.current_mode().unwrap(), AppControlMode::Disabled);
    }

    #[test]
    fn provider_current_mode_reflects_applied_policy() {
        let dir = std::env::temp_dir().join("sda-linux-test");
        let provider = LinuxAppControlProvider::new(dir);
        provider
            .apply_verified_policy(&payload())
            .expect("apply ok");
        assert_eq!(provider.current_mode().unwrap(), AppControlMode::Monitor);
    }

    #[test]
    fn provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LinuxAppControlProvider>();
    }

    #[test]
    fn policy_file_path_and_decisions_log_path_are_relative_to_dir() {
        let d = PathBuf::from("/tmp/x");
        assert_eq!(policy_file_path(&d), PathBuf::from("/tmp/x/policy.rules"));
        assert_eq!(
            decisions_log_path(&d),
            PathBuf::from("/tmp/x/decisions.log")
        );
    }
}
