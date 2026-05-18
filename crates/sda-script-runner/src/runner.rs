//! Script execution engine for `sda-script-runner`.
//!
//! See `docs/device-control.md` § 2 (Modules — `sda-script-runner`)
//! and § 4 (Signed-job lifecycle).
//!
//! [`ScriptRunner::run`] is the only public entry point. It:
//!
//! 1. Verifies the script body's Ed25519 signature against the
//!    pinned key (the runner refuses to execute unsigned scripts).
//! 2. Confirms the canonical name matches at least one
//!    [`Allowlist`] glob.
//! 3. Spawns the script under a hard wall-clock + output-byte
//!    budget. The script gets *no* PTY, *no* stdin, and *no*
//!    inherited environment.
//! 4. Captures stdout+stderr, truncates at the configured byte
//!    limit, and computes a SHA-256 over the **full** (untruncated)
//!    output so the server can verify integrity end-to-end.
//! 5. Returns a [`ScriptOutcome`] payload that the supervisor
//!    serializes onto the bus as `EventKind::ScriptRunResult` plus
//!    `EventKind::EvidenceRecord`.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::allowlist::Allowlist;

/// Default hard wall-clock limit, matching the proposal's 90 s default.
pub const DEFAULT_MAX_DURATION_SECS: u64 = 90;

/// Default hard output cap, matching the proposal's 1 MiB default.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Reason an output stream was truncated. Stable wire constants —
/// don't rename without bumping the wire schema.
pub mod truncation_reason {
    /// Output exceeded the configured byte budget.
    pub const SIZE_LIMIT: &str = "size_limit";
    /// Wall-clock budget elapsed; the process was killed mid-write.
    pub const TIMEOUT: &str = "timeout";
}

/// Length cap on the sanitized `job_id` portion of the on-disk
/// scratch filename. A `Uuid` is 36 chars; this leaves a comfortable
/// margin for any hash-style identifier a future producer might use
/// without risking a runaway filename on a hostile envelope.
const MAX_JOB_ID_LEN: usize = 64;

/// Length cap on the sanitized filesystem extension. Real-world
/// extensions never exceed this; the cap exists to defang a
/// pathological producer.
const MAX_EXTENSION_LEN: usize = 16;

/// Defang an envelope-provided path component before it is joined
/// into a filesystem path. Only `script_body` is covered by the
/// Ed25519 signature, so any other field becoming a filename — most
/// notably [`ScriptRequest::job_id`] and [`ScriptRequest::extension`]
/// — must be sanitized to avoid a `..` / `/` / `\` payload escaping
/// `work_dir` via [`std::path::Path::join`].
///
/// Strategy: keep ASCII alphanumeric plus `-` and `_`, drop
/// everything else (including all path separators on every host
/// platform), and truncate at `max_len` measured in *characters*
/// (the input is already filtered to ASCII so chars == bytes here).
fn sanitize_path_component(input: &str, max_len: usize) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(max_len)
        .collect()
}

/// Configuration for [`ScriptRunner`].
///
/// This is the in-process projection of
/// `sda_core::config::ScriptRunnerConfig`. We keep a separate type so
/// the crate compiles without depending on `sda-core` for unit tests
/// of the runner itself, and so future work can layer additional
/// runtime overrides on top without polluting the on-disk schema.
#[derive(Debug, Clone)]
pub struct ScriptRunnerConfig {
    /// Pinned Ed25519 public key bytes. The runner refuses to load
    /// without one.
    pub pinned_signing_key: [u8; PUBLIC_KEY_LENGTH],
    /// Compiled allow-list of canonical name globs.
    pub allowlist: Allowlist,
    /// Hard wall-clock limit for any single run.
    pub max_duration: Duration,
    /// Hard cap on combined stdout+stderr bytes captured.
    pub max_output_bytes: usize,
}

impl ScriptRunnerConfig {
    /// Build a runner config from the parsed agent config fields.
    ///
    /// Returns `Err` when `pinned_signing_key_hex` is missing,
    /// malformed, or the wrong length. The caller is expected to log
    /// and park the supervisor in that case rather than start the
    /// runner with a half-initialized key.
    pub fn from_parts(
        pinned_signing_key_hex: Option<&str>,
        allowlist_patterns: Vec<String>,
        max_duration_secs: u64,
        max_output_bytes: usize,
    ) -> Result<Self, ScriptRunnerError> {
        let hex = pinned_signing_key_hex.ok_or(ScriptRunnerError::MissingPinnedKey)?;
        let bytes = hex::decode(hex).map_err(|_| ScriptRunnerError::MalformedPinnedKey)?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(ScriptRunnerError::MalformedPinnedKey);
        }
        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&key).map_err(|_| ScriptRunnerError::MalformedPinnedKey)?;
        Ok(Self {
            pinned_signing_key: key,
            allowlist: Allowlist::new(allowlist_patterns),
            max_duration: Duration::from_secs(max_duration_secs.max(1)),
            max_output_bytes: max_output_bytes.max(1),
        })
    }
}

/// Single execution request.
#[derive(Debug, Clone)]
pub struct ScriptRequest {
    /// Job ID from the [`SignedActionJob`] that triggered the run.
    /// Surfaces verbatim in the result payload so the server can join
    /// it back to the originating action.
    pub job_id: String,
    /// Canonical script name (e.g. `sn360.diagnostics.tcp_ping`).
    /// Matched against [`ScriptRunnerConfig::allowlist`].
    pub canonical_name: String,
    /// Script body bytes, exactly as the control plane signed them.
    pub script_body: Vec<u8>,
    /// Detached Ed25519 signature over `script_body`.
    pub signature: Vec<u8>,
    /// Filesystem extension hint for the temp script (`sh`, `ps1`,
    /// …). The runner does not interpret it; it just makes the
    /// dropped file launchable on platforms that key off extension.
    pub extension: Option<String>,
    /// Arguments to pass to the script. Strictly positional; never
    /// merged with the agent's environment.
    pub args: Vec<String>,
}

/// Outcome of a single script run.
///
/// Serialized verbatim onto the bus as
/// `EventKind::ScriptRunResult { payload: serde_json::to_string(&out) }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptOutcome {
    /// Job ID copied from [`ScriptRequest::job_id`].
    pub job_id: String,
    /// Canonical script name copied from
    /// [`ScriptRequest::canonical_name`].
    pub canonical_name: String,
    /// Process exit code. `None` when the process was killed before
    /// it produced one (timeout or output-budget breach).
    pub exit_code: Option<i32>,
    /// `true` when the wall-clock budget tripped.
    pub timed_out: bool,
    /// `true` when the captured output reached the byte limit and
    /// the process was killed.
    pub output_truncated: bool,
    /// Mirror of [`output_truncated`] / [`timed_out`] as a stable
    /// string from [`truncation_reason`]. `None` when neither
    /// budget tripped.
    pub truncation_reason: Option<String>,
    /// Captured stdout, truncated at
    /// [`ScriptRunnerConfig::max_output_bytes`].
    pub stdout_truncated: String,
    /// Captured stderr, truncated at the same budget. The total of
    /// `stdout_truncated.len() + stderr_truncated.len()` is bounded
    /// by `max_output_bytes`.
    pub stderr_truncated: String,
    /// Lowercase-hex SHA-256 over the **full**, untruncated stdout
    /// stream. Computed independently from [`stderr_sha256`] so a
    /// downstream verifier can confirm pipe-level integrity without
    /// having to reconstruct an interleaved combined stream (which
    /// the agent never sees in a deterministic order anyway —
    /// stdout and stderr are drained on separate tasks).
    pub stdout_sha256: String,
    /// Lowercase-hex SHA-256 over the **full**, untruncated stderr
    /// stream. See [`stdout_sha256`].
    pub stderr_sha256: String,
    /// Wall-clock duration of the run.
    pub duration_secs: f64,
    /// Wall-clock time the runner started spawning the script.
    pub started_at: DateTime<Utc>,
    /// Wall-clock time the runner finished collecting output.
    pub finished_at: DateTime<Utc>,
}

/// Errors produced by [`ScriptRunner`].
#[derive(Debug, Error)]
pub enum ScriptRunnerError {
    /// `pinned_signing_key_hex` is `None` in config.
    #[error("script runner is missing a pinned signing key")]
    MissingPinnedKey,
    /// `pinned_signing_key_hex` is set but did not decode to a
    /// valid Ed25519 public key.
    #[error("pinned signing key is malformed (not 32 hex-encoded bytes of an Ed25519 key)")]
    MalformedPinnedKey,
    /// Signature is not 64 bytes / not a valid Ed25519 signature.
    #[error("script signature is malformed")]
    MalformedSignature,
    /// Signature did not verify against the pinned key.
    #[error("script signature did not verify against the pinned key")]
    SignatureMismatch,
    /// Canonical name did not match any allow-list glob.
    #[error("script {0:?} is not allow-listed")]
    NotAllowlisted(String),
    /// Failed to write the script to disk before spawning it.
    #[error("failed to materialize script on disk: {0}")]
    Io(#[from] std::io::Error),
    /// Failed to spawn the script process.
    #[error("failed to spawn script process: {0}")]
    Spawn(String),
}

/// In-process script execution engine.
///
/// Construct once with a [`ScriptRunnerConfig`] and call
/// [`ScriptRunner::run`] per script. The runner is `Send + Sync` and
/// holds no mutable state.
pub struct ScriptRunner {
    config: ScriptRunnerConfig,
    work_dir: PathBuf,
}

impl ScriptRunner {
    /// Construct a runner that drops scripts under `work_dir` before
    /// executing them.
    ///
    /// `work_dir` should be a per-agent scratch location that is
    /// writable by the agent user but not world-readable. The agent
    /// supervisor owns its lifetime.
    pub fn new(config: ScriptRunnerConfig, work_dir: PathBuf) -> Self {
        Self { config, work_dir }
    }

    /// Verify, allow-list-check, and execute `request`.
    pub async fn run(&self, request: ScriptRequest) -> Result<ScriptOutcome, ScriptRunnerError> {
        self.verify_signature(&request)?;
        if !self.config.allowlist.is_allowed(&request.canonical_name) {
            return Err(ScriptRunnerError::NotAllowlisted(
                request.canonical_name.clone(),
            ));
        }

        let script_path = self.materialize_script(&request).await?;
        let outcome = self.execute(&request, &script_path).await;

        // Best-effort cleanup. We never propagate cleanup errors —
        // the script result is what callers care about.
        if let Err(err) = tokio::fs::remove_file(&script_path).await {
            warn!(
                error = %err,
                path = %script_path.display(),
                "failed to remove script scratch file",
            );
        }

        outcome
    }

    fn verify_signature(&self, request: &ScriptRequest) -> Result<(), ScriptRunnerError> {
        if request.signature.len() != SIGNATURE_LENGTH {
            return Err(ScriptRunnerError::MalformedSignature);
        }
        let mut sig_bytes = [0u8; SIGNATURE_LENGTH];
        sig_bytes.copy_from_slice(&request.signature);
        let signature = Signature::from_bytes(&sig_bytes);
        let key = VerifyingKey::from_bytes(&self.config.pinned_signing_key)
            .map_err(|_| ScriptRunnerError::MalformedPinnedKey)?;
        key.verify(&request.script_body, &signature)
            .map_err(|_| ScriptRunnerError::SignatureMismatch)
    }

    async fn materialize_script(
        &self,
        request: &ScriptRequest,
    ) -> Result<PathBuf, ScriptRunnerError> {
        tokio::fs::create_dir_all(&self.work_dir).await?;
        // Use the lowercase-hex SHA-256 of the body so concurrent
        // jobs with the same body share a path without colliding on
        // distinct bodies. The file is removed post-run regardless.
        let mut hasher = Sha256::new();
        hasher.update(&request.script_body);
        let body_sha = hex::encode(hasher.finalize());
        // `job_id` and `extension` are NOT covered by the Ed25519
        // signature (only `script_body` is), so a hostile or buggy
        // producer could embed `..`, `/`, or `\` and `Path::join`
        // would faithfully resolve it relative to `work_dir`. Even
        // though the only known producer today (`SignedActionJob`)
        // ships a `Uuid` `job_id`, the runner refuses to trust an
        // unsigned envelope field that becomes a filesystem path.
        // Allow ASCII alphanumeric plus `-`/`_`, drop everything
        // else, and length-cap so an adversarial producer cannot
        // blow up the filename.
        let safe_job_id = sanitize_path_component(&request.job_id, MAX_JOB_ID_LEN);
        let mut filename = if safe_job_id.is_empty() {
            // The body hash alone is enough to disambiguate the file
            // when the envelope's `job_id` sanitises to nothing — we
            // prefer "still spawnable, just less debuggable" over
            // erroring out on an otherwise-valid signed body.
            format!("script-{body_sha}")
        } else {
            format!("script-{safe_job_id}-{body_sha}")
        };
        if let Some(ext) = &request.extension {
            let safe_ext = sanitize_path_component(ext, MAX_EXTENSION_LEN);
            if !safe_ext.is_empty() {
                filename.push('.');
                filename.push_str(&safe_ext);
            }
        }
        let path = self.work_dir.join(filename);
        tokio::fs::write(&path, &request.script_body).await?;

        // Best-effort: mark executable on Unix so we don't have to
        // shell out via `sh -c`.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&path).await?.permissions();
            perms.set_mode(0o700);
            tokio::fs::set_permissions(&path, perms).await?;
        }

        Ok(path)
    }

    async fn execute(
        &self,
        request: &ScriptRequest,
        script_path: &PathBuf,
    ) -> Result<ScriptOutcome, ScriptRunnerError> {
        let started_at = Utc::now();
        let started_instant = std::time::Instant::now();

        let mut cmd = Command::new(script_path);
        cmd.args(&request.args);
        // Belt-and-suspenders: fully detach stdin, scrub the
        // environment, and capture both stdout and stderr.
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.env_clear();
        cmd.kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| ScriptRunnerError::Spawn(e.to_string()))?;

        let stdout_pipe = child
            .stdout
            .take()
            .ok_or_else(|| ScriptRunnerError::Spawn("no stdout pipe attached".into()))?;
        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| ScriptRunnerError::Spawn("no stderr pipe attached".into()))?;

        let max = self.config.max_output_bytes;

        // Drain both pipes on background tasks so the wait+timeout
        // can race independently of the script's output behaviour.
        // Each drain records whether the byte budget tripped. The
        // full (untruncated) bytes are folded into a streaming
        // SHA-256 in `full_hasher`, so memory stays bounded by the
        // captured cap regardless of how much the script prints.
        let mut stdout_pipe = stdout_pipe;
        let mut stderr_pipe = stderr_pipe;
        let stdout_task = tokio::spawn(async move { drain_capped(&mut stdout_pipe, max).await });
        let stderr_task = tokio::spawn(async move { drain_capped(&mut stderr_pipe, max).await });

        let wait_result = timeout(self.config.max_duration, child.wait()).await;

        let (exit_code, timed_out) = match wait_result {
            Ok(Ok(status)) => (status.code(), false),
            Ok(Err(err)) => return Err(ScriptRunnerError::Spawn(err.to_string())),
            Err(_) => {
                // Timeout — kill the child to close its pipes so the
                // drain tasks below can finalize their hashes.
                let _ = child.start_kill();
                let _ = child.wait().await;
                (None, true)
            }
        };

        // Now that the child is reaped, the pipes are closed and the
        // drain tasks return promptly.
        let stdout = match stdout_task.await {
            Ok(Ok(d)) => d,
            Ok(Err(err)) => return Err(ScriptRunnerError::Io(err)),
            Err(err) => return Err(ScriptRunnerError::Spawn(err.to_string())),
        };
        let stderr = match stderr_task.await {
            Ok(Ok(d)) => d,
            Ok(Err(err)) => return Err(ScriptRunnerError::Io(err)),
            Err(err) => return Err(ScriptRunnerError::Spawn(err.to_string())),
        };

        let Drained {
            captured: stdout_bytes,
            hit_limit: stdout_hit,
            full_hasher: stdout_hasher,
        } = stdout;
        let Drained {
            captured: stderr_bytes,
            hit_limit: stderr_hit,
            full_hasher: stderr_hasher,
        } = stderr;

        let total = stdout_bytes.len() + stderr_bytes.len();
        // Strict `>` so a run that fills the combined budget exactly
        // does *not* report truncation. The `clamp_to` calls below
        // share the budget across the two pipes (stdout up to `max`,
        // stderr the remainder), so when `total == max` neither clamp
        // actually drops a byte and every emitted byte is preserved
        // verbatim in the wire payload. With `>=` we used to flag
        // `output_truncated = true` and stamp `truncation_reason =
        // "size_limit"` in that boundary case, lying to the audit
        // chain and any server-side verifier diffing the truncated
        // strings against the SHA-256-attested full byte counts.
        let mut output_truncated = total > max || stdout_hit || stderr_hit;
        if timed_out {
            output_truncated = true;
        }

        // Per-pipe SHA-256 over the full untruncated bytes that
        // passed through each pipe. We deliberately do *not* combine
        // them into a single hash here: stdout and stderr arrive on
        // separate drain tasks with no causal ordering, so any
        // "combined" hash would have to either buffer full bytes
        // (memory blowup on adversarial scripts) or pin one pipe's
        // ordering to the other (deadlocks if either pipe fills its
        // kernel buffer while we wait). Two independent digests let
        // the server verify each pipe end-to-end and compose them
        // however it wants.
        let stdout_sha256 = hex::encode(stdout_hasher.finalize());
        let stderr_sha256 = hex::encode(stderr_hasher.finalize());

        let finished_at = Utc::now();
        let duration_secs = started_instant.elapsed().as_secs_f64();

        // Collapse stdout+stderr into the documented combined budget
        // by clamping each side. We give stdout up to `max` and
        // stderr the remainder if any room remains; the byte-cap
        // drain already prevents either side from individually
        // exceeding `max`.
        let stdout_capped = clamp_to(stdout_bytes, max);
        let stdout_room = max.saturating_sub(stdout_capped.len());
        let stderr_capped = clamp_to(stderr_bytes, stdout_room);

        let truncation_reason = if timed_out {
            Some(truncation_reason::TIMEOUT.to_string())
        } else if output_truncated {
            Some(truncation_reason::SIZE_LIMIT.to_string())
        } else {
            None
        };

        debug!(
            job_id = %request.job_id,
            canonical_name = %request.canonical_name,
            exit_code = ?exit_code,
            timed_out,
            output_truncated,
            duration_secs,
            "script run finished"
        );

        Ok(ScriptOutcome {
            job_id: request.job_id.clone(),
            canonical_name: request.canonical_name.clone(),
            exit_code,
            timed_out,
            output_truncated,
            truncation_reason,
            stdout_truncated: String::from_utf8_lossy(&stdout_capped).into_owned(),
            stderr_truncated: String::from_utf8_lossy(&stderr_capped).into_owned(),
            stdout_sha256,
            stderr_sha256,
            duration_secs,
            started_at,
            finished_at,
        })
    }
}

/// Per-pipe drain result.
struct Drained {
    /// Captured bytes, bounded by the configured limit.
    captured: Vec<u8>,
    /// `true` when the byte budget tripped before EOF.
    hit_limit: bool,
    /// Streaming SHA-256 over the **full**, untruncated bytes that
    /// passed through this pipe. We hash on the fly so we never
    /// retain bytes beyond the captured cap.
    full_hasher: Sha256,
}

async fn drain_capped<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    cap: usize,
) -> std::io::Result<Drained> {
    let mut buf = [0u8; 8192];
    let mut captured: Vec<u8> = Vec::new();
    let mut full_hasher = Sha256::new();
    let mut hit_limit = false;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        full_hasher.update(&buf[..n]);
        if !hit_limit {
            let room = cap.saturating_sub(captured.len());
            if room == 0 {
                hit_limit = true;
            } else if n <= room {
                captured.extend_from_slice(&buf[..n]);
            } else {
                captured.extend_from_slice(&buf[..room]);
                hit_limit = true;
            }
        }
    }
    Ok(Drained {
        captured,
        hit_limit,
        full_hasher,
    })
}

fn clamp_to(mut bytes: Vec<u8>, cap: usize) -> Vec<u8> {
    if bytes.len() > cap {
        bytes.truncate(cap);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tempfile::TempDir;

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn config_for(key: &SigningKey, allow: Vec<&str>) -> ScriptRunnerConfig {
        let pub_hex = hex::encode(key.verifying_key().to_bytes());
        ScriptRunnerConfig::from_parts(
            Some(&pub_hex),
            allow.into_iter().map(|s| s.to_string()).collect(),
            5,
            64 * 1024,
        )
        .expect("config")
    }

    fn signed_request(
        key: &SigningKey,
        canonical_name: &str,
        body: &[u8],
        args: Vec<&str>,
    ) -> ScriptRequest {
        let signature = key.sign(body);
        ScriptRequest {
            job_id: "job-1".into(),
            canonical_name: canonical_name.to_string(),
            script_body: body.to_vec(),
            signature: signature.to_bytes().to_vec(),
            extension: Some("sh".into()),
            args: args.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn signed_script_runs_to_completion() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let runner = ScriptRunner::new(
            config_for(&key, vec!["sn360.diagnostics.*"]),
            tmp.path().to_path_buf(),
        );
        let req = signed_request(
            &key,
            "sn360.diagnostics.echo",
            b"#!/bin/sh\necho hello\n",
            vec![],
        );
        let outcome = runner.run(req).await.expect("ok");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(outcome.stdout_truncated.contains("hello"));
        assert!(!outcome.timed_out);
        assert!(!outcome.output_truncated);
        assert_eq!(outcome.truncation_reason, None);
        // Per-pipe digests are 64 lowercase-hex chars (32 bytes).
        // stdout produced "hello\n" so its hash equals SHA256("hello\n");
        // stderr is empty so its hash is the empty-string SHA-256.
        assert_eq!(outcome.stdout_sha256.len(), 64);
        assert_eq!(outcome.stderr_sha256.len(), 64);
        let mut h = Sha256::new();
        h.update(b"hello\n");
        assert_eq!(outcome.stdout_sha256, hex::encode(h.finalize()));
        assert_eq!(outcome.stderr_sha256, hex::encode(Sha256::new().finalize()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsigned_script_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let runner = ScriptRunner::new(
            config_for(&key, vec!["sn360.diagnostics.*"]),
            tmp.path().to_path_buf(),
        );
        let mut req = signed_request(
            &key,
            "sn360.diagnostics.echo",
            b"#!/bin/sh\necho hi\n",
            vec![],
        );
        req.signature = vec![0; SIGNATURE_LENGTH];
        let err = runner.run(req).await.unwrap_err();
        assert!(matches!(err, ScriptRunnerError::SignatureMismatch));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_pinned_key_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let trusted = make_signing_key();
        let attacker = make_signing_key();
        let runner = ScriptRunner::new(
            config_for(&trusted, vec!["sn360.diagnostics.*"]),
            tmp.path().to_path_buf(),
        );
        let req = signed_request(
            &attacker,
            "sn360.diagnostics.echo",
            b"#!/bin/sh\necho hi\n",
            vec![],
        );
        let err = runner.run(req).await.unwrap_err();
        assert!(matches!(err, ScriptRunnerError::SignatureMismatch));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn allowlist_match_required() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let runner = ScriptRunner::new(
            config_for(&key, vec!["sn360.diagnostics.*"]),
            tmp.path().to_path_buf(),
        );
        let req = signed_request(&key, "attacker.evil", b"#!/bin/sh\necho hi\n", vec![]);
        let err = runner.run(req).await.unwrap_err();
        assert!(matches!(err, ScriptRunnerError::NotAllowlisted(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_kills_long_running_process() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let mut cfg = config_for(&key, vec!["sn360.diagnostics.*"]);
        cfg.max_duration = Duration::from_millis(200);
        let runner = ScriptRunner::new(cfg, tmp.path().to_path_buf());
        let req = signed_request(
            &key,
            "sn360.diagnostics.sleep",
            b"#!/bin/sh\nsleep 30\n",
            vec![],
        );
        let outcome = runner.run(req).await.expect("ok");
        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_code, None);
        assert_eq!(
            outcome.truncation_reason.as_deref(),
            Some(truncation_reason::TIMEOUT)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn output_is_truncated_at_byte_limit() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let mut cfg = config_for(&key, vec!["sn360.diagnostics.*"]);
        cfg.max_output_bytes = 64;
        let runner = ScriptRunner::new(cfg, tmp.path().to_path_buf());
        // Print a 20 KB block of As to stdout.
        let body = b"#!/bin/sh\nprintf 'A%.0s' $(seq 1 20000)\n";
        let req = signed_request(&key, "sn360.diagnostics.echo", body, vec![]);
        let outcome = runner.run(req).await.expect("ok");
        assert!(outcome.output_truncated);
        assert_eq!(
            outcome.truncation_reason.as_deref(),
            Some(truncation_reason::SIZE_LIMIT)
        );
        // stdout was clamped to 64 bytes.
        assert!(outcome.stdout_truncated.len() <= 64);
        // Per-pipe SHA-256 is computed over the *untruncated* 20 KB
        // stream, so the recorded hash must equal SHA256(b"A" * 20000).
        let mut full = Sha256::new();
        for _ in 0..20_000 {
            full.update(b"A");
        }
        assert_eq!(outcome.stdout_sha256, hex::encode(full.finalize()));
        assert_eq!(outcome.stdout_sha256.len(), 64);
        // stderr was empty, so its hash is the empty-string SHA-256.
        assert_eq!(outcome.stderr_sha256, hex::encode(Sha256::new().finalize()));
    }

    /// Regression guard for the `total > max` (was `>=`) boundary in
    /// `execute`. Each per-pipe drain is independently capped at
    /// `max`, so a run that produces `N` bytes on stdout and
    /// `max - N` bytes on stderr never trips either pipe's
    /// `hit_limit`. Pre-fix the combined `total >= max` check still
    /// flagged `output_truncated = true` and stamped
    /// `truncation_reason = "size_limit"` even though every emitted
    /// byte was preserved verbatim by the subsequent `clamp_to`
    /// calls — lying to the audit chain. With strict `>` the
    /// boundary case correctly reports no truncation.
    #[tokio::test(flavor = "current_thread")]
    async fn output_exactly_filling_combined_budget_is_not_flagged_truncated() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let mut cfg = config_for(&key, vec!["sn360.diagnostics.*"]);
        cfg.max_output_bytes = 32;
        let runner = ScriptRunner::new(cfg, tmp.path().to_path_buf());
        // 16 bytes of 'A' on stdout + 16 bytes of 'B' on stderr =
        // exactly 32 bytes combined, matching the configured cap.
        // `printf` is used (not `echo`) to avoid the trailing newline
        // that would push us off-boundary.
        let body = b"#!/bin/sh\n\
            printf 'A%.0s' $(seq 1 16)\n\
            printf 'B%.0s' $(seq 1 16) >&2\n";
        let req = signed_request(&key, "sn360.diagnostics.echo", body, vec![]);
        let outcome = runner.run(req).await.expect("ok");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(
            !outcome.output_truncated,
            "filling the budget exactly must not flag truncation",
        );
        assert_eq!(outcome.truncation_reason, None);
        // Sanity-check the wire payload: every byte made it through.
        assert_eq!(outcome.stdout_truncated.len(), 16);
        assert_eq!(outcome.stderr_truncated.len(), 16);
        assert_eq!(outcome.stdout_truncated, "A".repeat(16));
        assert_eq!(outcome.stderr_truncated, "B".repeat(16));
        // Per-pipe SHA-256s lock in that the digests match the
        // captured strings, so a server-side verifier cross-checking
        // the two does not see a contradiction at the boundary.
        let mut a = Sha256::new();
        a.update(b"A".repeat(16));
        assert_eq!(outcome.stdout_sha256, hex::encode(a.finalize()));
        let mut b = Sha256::new();
        b.update(b"B".repeat(16));
        assert_eq!(outcome.stderr_sha256, hex::encode(b.finalize()));
    }

    /// Companion to the boundary test above: exceeding the combined
    /// budget by even a single byte must still flag truncation.
    /// Locks in that the strict `>` does not regress in the other
    /// direction.
    #[tokio::test(flavor = "current_thread")]
    async fn output_exceeding_combined_budget_by_one_byte_flags_truncation() {
        let tmp = TempDir::new().unwrap();
        let key = make_signing_key();
        let mut cfg = config_for(&key, vec!["sn360.diagnostics.*"]);
        cfg.max_output_bytes = 32;
        let runner = ScriptRunner::new(cfg, tmp.path().to_path_buf());
        // 17 bytes on stdout + 16 bytes on stderr = 33 bytes total,
        // one byte past the 32-byte combined cap. Neither pipe trips
        // its individual `hit_limit` (each is well under 32).
        let body = b"#!/bin/sh\n\
            printf 'A%.0s' $(seq 1 17)\n\
            printf 'B%.0s' $(seq 1 16) >&2\n";
        let req = signed_request(&key, "sn360.diagnostics.echo", body, vec![]);
        let outcome = runner.run(req).await.expect("ok");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(
            outcome.output_truncated,
            "one byte past the combined cap must flag truncation",
        );
        assert_eq!(
            outcome.truncation_reason.as_deref(),
            Some(truncation_reason::SIZE_LIMIT)
        );
    }

    #[test]
    fn missing_pinned_key_errors() {
        let err = ScriptRunnerConfig::from_parts(None, vec![], 90, 1024).unwrap_err();
        assert!(matches!(err, ScriptRunnerError::MissingPinnedKey));
    }

    #[test]
    fn malformed_pinned_key_errors() {
        let err = ScriptRunnerConfig::from_parts(Some("zz"), vec![], 90, 1024).unwrap_err();
        assert!(matches!(err, ScriptRunnerError::MalformedPinnedKey));
    }

    #[test]
    fn sanitize_path_component_strips_path_separators_and_dots() {
        // `..`, `/`, `\` must not survive — they are the
        // payloads `materialize_script` is defending against.
        assert_eq!(sanitize_path_component("../etc/passwd", 64), "etcpasswd");
        assert_eq!(sanitize_path_component("..", 64), "");
        assert_eq!(
            sanitize_path_component("a/b\\c..d", 64),
            "abcd",
            "all path separators and dots dropped",
        );
    }

    #[test]
    fn sanitize_path_component_keeps_uuid_shaped_input_intact() {
        // Today's only producer ships a `Uuid` `job_id`; the
        // sanitizer must not corrupt that happy path.
        let uuid = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        assert_eq!(sanitize_path_component(uuid, MAX_JOB_ID_LEN), uuid);
    }

    #[test]
    fn sanitize_path_component_caps_length_for_runaway_input() {
        // 1 KiB of 'a' must collapse to MAX_JOB_ID_LEN bytes so a
        // hostile producer cannot blow up the on-disk filename.
        let huge = "a".repeat(1024);
        let out = sanitize_path_component(&huge, MAX_JOB_ID_LEN);
        assert_eq!(out.len(), MAX_JOB_ID_LEN);
    }

    #[test]
    fn sanitize_path_component_drops_unicode_and_control_bytes() {
        // Non-ASCII (CJK / emoji) and control chars are dropped
        // entirely. The sanitizer is intentionally restrictive.
        assert_eq!(sanitize_path_component("héllo🦀world", 64), "hlloworld");
        assert_eq!(sanitize_path_component("a\nb\tc\0d", 64), "abcd");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malicious_job_id_cannot_escape_work_dir() {
        let tmp = TempDir::new().unwrap();
        let work_dir = tmp.path().to_path_buf();
        let key = make_signing_key();
        let runner = ScriptRunner::new(
            config_for(&key, vec!["sn360.diagnostics.*"]),
            work_dir.clone(),
        );
        let body = b"#!/bin/sh\necho hello\n";
        let mut req = signed_request(&key, "sn360.diagnostics.echo", body, vec![]);
        // Hostile producer tries to escape `work_dir` via path
        // separators in the unsigned `job_id` envelope field.
        req.job_id = "../../../../../tmp/pwned".into();
        // And via a hostile extension. Both fields are unsigned.
        req.extension = Some("../sh".into());
        let outcome = runner.run(req).await.expect("ok");
        assert_eq!(outcome.exit_code, Some(0));
        // Best evidence the sanitizer worked: nothing was written
        // outside `work_dir`. After `run()` finishes the runner
        // removes the script file, so we expect the work dir to be
        // empty (no escaped artifacts above it either, but the temp
        // dir scope guarantees that).
        let entries: Vec<_> = std::fs::read_dir(&work_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "scratch files leaked into work_dir: {entries:?}",
        );
    }
}
