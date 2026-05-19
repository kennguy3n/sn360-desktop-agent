//! User-consent gate for remote-support sessions.
//!
//! `docs/device-control.md` § 9 mandates that **every** remote-support session
//! show a consent banner and block until the end-user accepts. This
//! module owns that gate. Phase 4 ships:
//!
//! * [`ConsentManager`] — the orchestration surface; takes a
//!   pluggable [`ConsentPrompt`] so production code can wire it to a
//!   real desktop UI while tests use [`AutoApproveConsentPrompt`] /
//!   [`AutoDenyConsentPrompt`].
//! * [`ConsentDecision`] — the outcome of a single prompt. Captured
//!   verbatim in evidence / audit records.
//!
//! The Phase-4 default prompt — [`StubConsentPrompt`] — denies every
//! request, matching the agent's fail-closed posture: if the
//! operator wires a `RemoteSupportModule` without supplying a real
//! prompt, no remote-support session ever activates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Outcome of a single consent prompt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    /// User accepted the prompt; the session may proceed.
    Approved,
    /// User actively dismissed / refused the prompt.
    Denied,
    /// The prompt timed out before the user responded.
    TimedOut,
}

/// Pluggable surface for asking the user whether a session may
/// proceed.
///
/// Implementations MUST be `Send + Sync` because the supervisor
/// holds them in a `Box<dyn ConsentPrompt>`. The Phase-4 default
/// is [`StubConsentPrompt`]; real implementations will land in
/// later phases (one per OS, wired into the desktop notification
/// surface).
pub trait ConsentPrompt: Send + Sync {
    /// Show a prompt for `operator_id` and `session_id` and block
    /// until the user responds (or the implementation's internal
    /// timeout elapses).
    fn ask(&self, session_id: &str, operator_id: &str) -> ConsentDecision;
}

/// Phase-4 default prompt: deny every request.
///
/// Used when the operator has wired a `RemoteSupportModule` but
/// has not yet supplied a real desktop UI surface. Failing closed
/// here matches the agent's privacy-first posture.
#[derive(Debug, Default)]
pub struct StubConsentPrompt;

impl ConsentPrompt for StubConsentPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        ConsentDecision::Denied
    }
}

/// Platform-native consent dialog.
///
/// Uses OS-level dialog commands to present a consent prompt to the
/// end user:
/// - **macOS**: `osascript` driving an NSAlert via AppleScript
/// - **Windows**: PowerShell `MessageBox` via `Add-Type`
/// - **Linux**: `zenity` (GTK) with `kdialog` (KDE) fallback
///
/// Falls back to [`ConsentDecision::Denied`] if no dialog tool is
/// available, preserving the fail-closed posture.
#[derive(Debug, Default)]
pub struct NativeConsentPrompt {
    /// Timeout in seconds for the dialog. Defaults to 120.
    pub timeout_secs: u64,
}

impl NativeConsentPrompt {
    pub fn new() -> Self {
        Self { timeout_secs: 120 }
    }

    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

impl ConsentPrompt for NativeConsentPrompt {
    fn ask(&self, session_id: &str, operator_id: &str) -> ConsentDecision {
        let title = "SN360 Remote Support";
        let message = format!(
            "A support analyst ({}) is requesting remote access to \
             this device.\n\nSession: {}\n\nDo you want to allow this?",
            operator_id, session_id,
        );
        let timeout = std::time::Duration::from_secs(self.timeout_secs);

        match native_dialog(title, &message, timeout) {
            Some(true) => ConsentDecision::Approved,
            Some(false) => ConsentDecision::Denied,
            None => ConsentDecision::TimedOut,
        }
    }
}

/// Show a platform-native yes/no dialog. Returns `Some(true)` for
/// yes, `Some(false)` for no/cancel, `None` on timeout or if no
/// dialog tool is available.
fn native_dialog(title: &str, message: &str, timeout: std::time::Duration) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        macos_dialog(title, message, timeout)
    }
    #[cfg(target_os = "windows")]
    {
        windows_dialog(title, message, timeout)
    }
    #[cfg(target_os = "linux")]
    {
        linux_dialog(title, message, timeout)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = (title, message, timeout);
        tracing::warn!("native consent dialog: unsupported platform, denying");
        Some(false)
    }
}

#[cfg(target_os = "macos")]
fn macos_dialog(title: &str, message: &str, timeout: std::time::Duration) -> Option<bool> {
    let script = format!(
        r#"display dialog "{}" with title "{}" buttons {{"Deny", "Allow"}} default button "Deny" giving up after {}"#,
        message.replace('\\', "\\\\").replace('"', "\\\""),
        title.replace('\\', "\\\\").replace('"', "\\\""),
        timeout.as_secs(),
    );
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("gave up:true") {
                None
            } else if stdout.contains("Allow") {
                Some(true)
            } else {
                Some(false)
            }
        }
        Ok(_) => Some(false),
        Err(e) => {
            tracing::warn!("osascript failed: {e}");
            Some(false)
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_dialog(title: &str, message: &str, timeout: std::time::Duration) -> Option<bool> {
    let ps_script = format!(
        r#"Add-Type -AssemblyName System.Windows.Forms; $r = [System.Windows.Forms.MessageBox]::Show('{}', '{}', 'YesNo', 'Question'); if ($r -eq 'Yes') {{ exit 0 }} else {{ exit 1 }}"#,
        message.replace('\'', "''"),
        title.replace('\'', "''"),
    );
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output();
    match output {
        Ok(o) => Some(o.status.success()),
        Err(e) => {
            tracing::warn!("powershell dialog failed: {e}");
            Some(false)
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_dialog(title: &str, message: &str, timeout: std::time::Duration) -> Option<bool> {
    // Try zenity first (GTK), then kdialog (KDE).
    if let Ok(output) = std::process::Command::new("zenity")
        .args([
            "--question",
            "--title",
            title,
            "--text",
            message,
            "--ok-label",
            "Allow",
            "--cancel-label",
            "Deny",
            "--timeout",
            &timeout.as_secs().to_string(),
        ])
        .output()
    {
        return match output.status.code() {
            Some(0) => Some(true),  // Allow
            Some(1) => Some(false), // Deny
            Some(5) => None,        // Timeout
            _ => Some(false),
        };
    }

    if let Ok(output) = std::process::Command::new("kdialog")
        .args(["--title", title, "--yesno", message])
        .output()
    {
        return Some(output.status.success());
    }

    tracing::warn!("no dialog tool found (zenity / kdialog); denying consent");
    Some(false)
}

/// Test helper: always approve. Not exposed in production builds.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct AutoApproveConsentPrompt;

#[cfg(test)]
impl ConsentPrompt for AutoApproveConsentPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        ConsentDecision::Approved
    }
}

/// Test helper: always deny. Not exposed in production builds.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct AutoDenyConsentPrompt;

#[cfg(test)]
impl ConsentPrompt for AutoDenyConsentPrompt {
    fn ask(&self, _session_id: &str, _operator_id: &str) -> ConsentDecision {
        ConsentDecision::Denied
    }
}

/// Audit record for a single consent prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub session_id: String,
    pub operator_id: String,
    pub decision: ConsentDecision,
    pub asked_at: DateTime<Utc>,
}

/// Stateful consent orchestrator.
///
/// Wraps a [`ConsentPrompt`] and records every decision in an
/// in-memory audit list so the supervisor can include the full
/// chain of prompts in evidence records.
pub struct ConsentManager {
    prompt: Box<dyn ConsentPrompt>,
    history: Vec<ConsentRecord>,
}

impl std::fmt::Debug for ConsentManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentManager")
            .field("history_len", &self.history.len())
            .finish()
    }
}

impl ConsentManager {
    /// Build a manager backed by `prompt`.
    pub fn new(prompt: Box<dyn ConsentPrompt>) -> Self {
        Self {
            prompt,
            history: Vec::new(),
        }
    }

    /// Build a manager backed by [`StubConsentPrompt`] (deny-all).
    pub fn deny_all() -> Self {
        Self::new(Box::new(StubConsentPrompt))
    }

    /// Show a prompt and record the decision.
    pub fn ask(&mut self, session_id: &str, operator_id: &str) -> ConsentDecision {
        let decision = self.prompt.ask(session_id, operator_id);
        self.history.push(ConsentRecord {
            session_id: session_id.into(),
            operator_id: operator_id.into(),
            decision: decision.clone(),
            asked_at: Utc::now(),
        });
        decision
    }

    /// Read-only view of all decisions recorded so far. Useful for
    /// evidence emission.
    pub fn history(&self) -> &[ConsentRecord] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_prompt_always_denies() {
        let p = StubConsentPrompt;
        assert_eq!(p.ask("s", "o"), ConsentDecision::Denied);
    }

    #[test]
    fn auto_approve_helper_approves() {
        let p = AutoApproveConsentPrompt;
        assert_eq!(p.ask("s", "o"), ConsentDecision::Approved);
    }

    #[test]
    fn auto_deny_helper_denies() {
        let p = AutoDenyConsentPrompt;
        assert_eq!(p.ask("s", "o"), ConsentDecision::Denied);
    }

    #[test]
    fn manager_records_each_decision() {
        let mut m = ConsentManager::new(Box::new(AutoApproveConsentPrompt));
        let d1 = m.ask("s1", "op@example.com");
        let d2 = m.ask("s2", "op@example.com");
        assert_eq!(d1, ConsentDecision::Approved);
        assert_eq!(d2, ConsentDecision::Approved);
        assert_eq!(m.history().len(), 2);
        assert_eq!(m.history()[0].session_id, "s1");
        assert_eq!(m.history()[1].session_id, "s2");
    }

    #[test]
    fn deny_all_factory_uses_stub_prompt() {
        let mut m = ConsentManager::deny_all();
        assert_eq!(m.ask("s", "o"), ConsentDecision::Denied);
    }

    #[test]
    fn decision_round_trips_through_json() {
        for d in [
            ConsentDecision::Approved,
            ConsentDecision::Denied,
            ConsentDecision::TimedOut,
        ] {
            let json = serde_json::to_string(&d).expect("encode");
            let back: ConsentDecision = serde_json::from_str(&json).expect("decode");
            assert_eq!(d, back);
        }
    }

    #[test]
    fn record_round_trips_through_json() {
        let r = ConsentRecord {
            session_id: "s".into(),
            operator_id: "o".into(),
            decision: ConsentDecision::Approved,
            asked_at: Utc::now(),
        };
        let json = serde_json::to_string(&r).expect("encode");
        let back: ConsentRecord = serde_json::from_str(&json).expect("decode");
        assert_eq!(r, back);
    }
}
