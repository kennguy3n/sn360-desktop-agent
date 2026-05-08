//! Windows app-control backend: WDAC (Windows Defender Application
//! Control) with an AppLocker fallback for legacy Windows builds
//! (Task 4.7).
//!
//! The translation layer is host-OS-agnostic so unit tests can run
//! anywhere — only the actual policy push (writing the XML to a temp
//! file and invoking PowerShell) is gated on `target_os = "windows"`.
//!
//! ## Translation
//!
//! [`build_wdac_document`] / [`render_wdac_xml`] convert an
//! [`AppControlPolicyPayload`] into the WDAC schema's
//! `<SiPolicy>` document, expressing each [`AppControlRule`] as a
//! `<FileRules>` entry plus a `<Signers>` block where applicable.
//! [`build_applocker_document`] / [`render_applocker_xml`] produce
//! the equivalent `<AppLockerPolicy>` document for hosts on which
//! WDAC is unavailable (Windows Server 2012 R2, Windows 10 < 1903).
//!
//! ## Backend selection
//!
//! [`select_backend`] picks WDAC for Windows 10 build ≥ 18362
//! (1903 / "May 2019 Update", the first build where the modern
//! signed-policy stack is GA) and AppLocker otherwise.
//!
//! ## Provider
//!
//! [`WdacAppControlProvider`] implements
//! [`sda_pal::app_control::AppControlProvider`]. On Windows it
//! writes the rendered XML to `staging_dir`, then invokes the
//! PowerShell sequence built by [`powershell_apply_wdac_commands`]
//! (or [`powershell_apply_applocker_commands`]). On non-Windows
//! hosts it records the rendered artifact in memory and returns
//! `Ok(())` so cross-platform tests exercise the full translation
//! path.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use sda_pal::app_control::{
    AppControlError, AppControlMode, AppControlPolicyPayload, AppControlProvider, AppControlRule,
};

/// Minimum Windows 10 build that ships the modern WDAC signed-policy
/// stack (1903, 18362). Earlier builds fall back to AppLocker.
pub const MIN_WDAC_WINDOWS_BUILD: u32 = 18_362;

/// Top-level GUID assigned to every policy document the agent
/// emits. The control-plane signs the bundle so the GUID does not
/// need to rotate per-policy — it identifies the *agent* policy
/// stream.
pub const POLICY_BASE_ID: &str = "{A244370E-44C9-4C06-B551-F6016E563076}";

/// Name embedded in the rendered `<PolicyName>` field. Surfaces in
/// `Get-CIPolicyInfo` and the Windows event log.
pub const POLICY_DISPLAY_NAME: &str = "SN360 Desktop Agent — Application Control";

/// Backend used to apply a verified policy on a Windows host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WdacBackend {
    /// Windows Defender Application Control (modern signed-policy).
    Wdac,
    /// AppLocker (legacy; pre-WDAC Windows builds).
    AppLocker,
}

impl WdacBackend {
    /// Stable lowercase string used in logs / wire payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            WdacBackend::Wdac => "wdac",
            WdacBackend::AppLocker => "applocker",
        }
    }
}

/// Pick the backend appropriate for a given Windows build number.
///
/// `os_build` is the Windows 10 / 11 build number (e.g. `19045` for
/// 22H2). Build numbers < [`MIN_WDAC_WINDOWS_BUILD`] fall back to
/// AppLocker.
pub fn select_backend(os_build: u32) -> WdacBackend {
    if os_build >= MIN_WDAC_WINDOWS_BUILD {
        WdacBackend::Wdac
    } else {
        WdacBackend::AppLocker
    }
}

/// Subject kinds the translator understands.
///
/// Anything else is treated as an opaque SHA-256 — WDAC will reject
/// the rule at policy-merge time, which surfaces as a clear
/// `New-CIPolicy` failure rather than silent allow-list drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    Sha256,
    Sha1,
    PublisherCommonName,
    OriginalFileName,
    Path,
    PackageFamilyName,
    Unknown,
}

impl SubjectKind {
    fn from_prefix(prefix: &str) -> Self {
        match prefix {
            "sha256" => SubjectKind::Sha256,
            "sha1" => SubjectKind::Sha1,
            "publisher" | "cn" => SubjectKind::PublisherCommonName,
            "original_file_name" | "ofn" => SubjectKind::OriginalFileName,
            "path" => SubjectKind::Path,
            "package_family_name" | "pfn" => SubjectKind::PackageFamilyName,
            _ => SubjectKind::Unknown,
        }
    }
}

/// One translated [`AppControlRule`] entry, normalised into a
/// shape both backends can consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdacRuleEntry {
    pub kind: SubjectKind,
    pub value: String,
    pub allow: bool,
    pub reason: String,
    /// Stable per-rule identifier (`ID_ALLOW_A_0`, `ID_DENY_S_3`,
    /// etc.) used as the `Id` attribute on the WDAC `<Allow>` /
    /// `<Deny>` element.
    pub id: String,
}

/// Parse a `kind:value` subject string. Returns
/// `(SubjectKind::Unknown, original)` for unrecognised prefixes.
pub fn parse_subject(s: &str) -> (SubjectKind, String) {
    if let Some((prefix, rest)) = s.split_once(':') {
        let kind = SubjectKind::from_prefix(prefix.trim());
        if matches!(kind, SubjectKind::Unknown) {
            return (SubjectKind::Unknown, s.to_string());
        }
        return (kind, rest.trim().to_string());
    }
    // No prefix → treat as raw SHA-256.
    (SubjectKind::Sha256, s.to_string())
}

/// A translated WDAC policy document, ready to be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdacPolicyDocument {
    pub policy_id: String,
    pub policy_name: String,
    pub version: u64,
    pub mode: AppControlMode,
    pub issued_at: DateTime<Utc>,
    pub rules: Vec<WdacRuleEntry>,
}

/// AppLocker fallback document. Only file-publisher and file-hash
/// rules are emitted; richer subjects (path, package family name)
/// are dropped with a logged warning during `build_*` because
/// AppLocker's schema does not support them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppLockerPolicyDocument {
    pub policy_id: String,
    pub mode: AppControlMode,
    pub rules: Vec<WdacRuleEntry>,
    /// Subjects that AppLocker cannot represent. Returned to the
    /// caller so the supervisor can include them in the evidence
    /// record and the operator dashboard.
    pub dropped_subjects: Vec<String>,
}

fn translate_rules(payload: &AppControlPolicyPayload) -> Vec<WdacRuleEntry> {
    payload
        .rules
        .iter()
        .enumerate()
        .map(|(i, rule)| translate_rule(rule, i))
        .collect()
}

fn translate_rule(rule: &AppControlRule, index: usize) -> WdacRuleEntry {
    let (kind, value) = parse_subject(&rule.subject);
    let id = format!(
        "ID_{}_{}_{}",
        if rule.allow { "ALLOW" } else { "DENY" },
        kind_short(kind),
        index
    );
    WdacRuleEntry {
        kind,
        value,
        allow: rule.allow,
        reason: rule.reason.clone(),
        id,
    }
}

fn kind_short(k: SubjectKind) -> &'static str {
    match k {
        SubjectKind::Sha256 => "S256",
        SubjectKind::Sha1 => "S1",
        SubjectKind::PublisherCommonName => "PUB",
        SubjectKind::OriginalFileName => "OFN",
        SubjectKind::Path => "PATH",
        SubjectKind::PackageFamilyName => "PFN",
        SubjectKind::Unknown => "UNK",
    }
}

/// Build a [`WdacPolicyDocument`] from a verified payload.
pub fn build_wdac_document(payload: &AppControlPolicyPayload) -> WdacPolicyDocument {
    WdacPolicyDocument {
        policy_id: POLICY_BASE_ID.to_string(),
        policy_name: POLICY_DISPLAY_NAME.to_string(),
        version: payload.version,
        mode: payload.target_mode,
        issued_at: payload.issued_at,
        rules: translate_rules(payload),
    }
}

/// Build an [`AppLockerPolicyDocument`]. Subjects that AppLocker
/// cannot represent (path, package family name, original file name,
/// unknown) are recorded in `dropped_subjects` so the supervisor
/// can surface them on the evidence record.
pub fn build_applocker_document(payload: &AppControlPolicyPayload) -> AppLockerPolicyDocument {
    let translated = translate_rules(payload);
    let mut rules = Vec::with_capacity(translated.len());
    let mut dropped = Vec::new();
    for r in translated {
        if matches!(
            r.kind,
            SubjectKind::Sha256 | SubjectKind::Sha1 | SubjectKind::PublisherCommonName
        ) {
            rules.push(r);
        } else {
            dropped.push(format!("{}:{}", kind_short(r.kind).to_lowercase(), r.value));
        }
    }
    AppLockerPolicyDocument {
        policy_id: POLICY_BASE_ID.to_string(),
        mode: payload.target_mode,
        rules,
        dropped_subjects: dropped,
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Render a [`WdacPolicyDocument`] to the canonical `<SiPolicy>` XML.
///
/// The output is suitable as input to `ConvertFrom-CIPolicy` and
/// `Set-CIPolicyIdInfo`. The XML schema mirrors `New-CIPolicy`'s
/// output but is constructed deterministically so policy diffs are
/// reviewable in evidence records.
pub fn render_wdac_xml(doc: &WdacPolicyDocument) -> String {
    let policy_type_id = if doc.mode == AppControlMode::Enforce {
        "0"
    } else {
        "1"
    };
    let mut out = String::new();
    out.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    out.push('\n');
    out.push_str(r#"<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">"#);
    out.push('\n');
    out.push_str(&format!(
        "  <VersionEx>10.0.0.{}</VersionEx>\n",
        doc.version
    ));
    out.push_str(&format!(
        "  <PolicyTypeID>{}</PolicyTypeID>\n",
        xml_escape(&doc.policy_id)
    ));
    out.push_str(&format!(
        "  <PolicyID>{}</PolicyID>\n",
        xml_escape(&doc.policy_id)
    ));
    out.push_str(&format!(
        "  <BasePolicyID>{}</BasePolicyID>\n",
        xml_escape(&doc.policy_id)
    ));
    out.push_str(&format!(
        "  <FriendlyName>{}</FriendlyName>\n",
        xml_escape(&doc.policy_name)
    ));
    out.push_str(&format!(
        "  <Issued>{}</Issued>\n",
        doc.issued_at.to_rfc3339()
    ));
    out.push_str(&format!(
        "  <Mode>{}</Mode>\n",
        xml_escape(doc.mode.as_str())
    ));
    out.push_str(&format!("  <PolicyType>{}</PolicyType>\n", policy_type_id));

    out.push_str("  <FileRules>\n");
    for r in &doc.rules {
        let (tag, attr_name) = match r.kind {
            SubjectKind::Sha256 => ("FileAttrib", "Hash"),
            SubjectKind::Sha1 => ("FileAttrib", "Hash"),
            SubjectKind::PublisherCommonName => ("FileAttrib", "PublisherName"),
            SubjectKind::OriginalFileName => ("FileAttrib", "FileName"),
            SubjectKind::Path => ("FileAttrib", "Path"),
            SubjectKind::PackageFamilyName => ("FileAttrib", "PackageFamilyName"),
            SubjectKind::Unknown => ("FileAttrib", "Hash"),
        };
        let action = if r.allow { "Allow" } else { "Deny" };
        out.push_str(&format!(
            "    <{tag} ID=\"{id}\" FriendlyName=\"{reason}\" {attr}=\"{val}\" Action=\"{action}\"/>\n",
            tag = tag,
            id = xml_escape(&r.id),
            reason = xml_escape(&r.reason),
            attr = attr_name,
            val = xml_escape(&r.value),
            action = action,
        ));
    }
    out.push_str("  </FileRules>\n");
    out.push_str("</SiPolicy>\n");
    out
}

/// Render an [`AppLockerPolicyDocument`] to AppLocker XML.
///
/// AppLocker uses `<RuleCollection>` per file kind. We always emit
/// `<RuleCollection Type="Exe">` since the agent only authorises
/// executable binaries today; richer types (Msi, Script, Appx) can
/// be added without a wire-format change.
pub fn render_applocker_xml(doc: &AppLockerPolicyDocument) -> String {
    let mut out = String::new();
    out.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    out.push('\n');
    out.push_str(&format!(
        "<AppLockerPolicy Version=\"1\" Id=\"{}\">\n",
        xml_escape(&doc.policy_id)
    ));
    let enforcement_mode = match doc.mode {
        AppControlMode::Enforce => "Enabled",
        AppControlMode::Monitor => "AuditOnly",
        AppControlMode::Disabled => "NotConfigured",
    };
    out.push_str(&format!(
        "  <RuleCollection Type=\"Exe\" EnforcementMode=\"{}\">\n",
        enforcement_mode
    ));
    for r in &doc.rules {
        let action = if r.allow { "Allow" } else { "Deny" };
        match r.kind {
            SubjectKind::Sha256 | SubjectKind::Sha1 => {
                out.push_str(&format!(
                    "    <FileHashRule Id=\"{id}\" Name=\"{reason}\" Description=\"{reason}\" UserOrGroupSid=\"S-1-1-0\" Action=\"{action}\">\n",
                    id = xml_escape(&r.id),
                    reason = xml_escape(&r.reason),
                    action = action,
                ));
                out.push_str("      <Conditions>\n");
                out.push_str(&format!(
                    "        <FileHashCondition><FileHash Type=\"{ty}\" Data=\"{data}\" SourceFileName=\"\" SourceFileLength=\"0\"/></FileHashCondition>\n",
                    ty = if matches!(r.kind, SubjectKind::Sha256) { "SHA256" } else { "SHA1" },
                    data = xml_escape(&r.value),
                ));
                out.push_str("      </Conditions>\n");
                out.push_str("    </FileHashRule>\n");
            }
            SubjectKind::PublisherCommonName => {
                out.push_str(&format!(
                    "    <FilePublisherRule Id=\"{id}\" Name=\"{reason}\" Description=\"{reason}\" UserOrGroupSid=\"S-1-1-0\" Action=\"{action}\">\n",
                    id = xml_escape(&r.id),
                    reason = xml_escape(&r.reason),
                    action = action,
                ));
                out.push_str("      <Conditions>\n");
                out.push_str(&format!(
                    "        <FilePublisherCondition PublisherName=\"{val}\" ProductName=\"*\" BinaryName=\"*\"><BinaryVersionRange LowSection=\"*\" HighSection=\"*\"/></FilePublisherCondition>\n",
                    val = xml_escape(&r.value),
                ));
                out.push_str("      </Conditions>\n");
                out.push_str("    </FilePublisherRule>\n");
            }
            _ => {}
        }
    }
    out.push_str("  </RuleCollection>\n");
    out.push_str("</AppLockerPolicy>\n");
    out
}

/// One PowerShell command, modelled as `program + args` so callers
/// can audit the full argv before invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerShellCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl PowerShellCommand {
    /// Render the command back to a single shell-quoted line.
    /// Used for evidence records and dry-run logs.
    pub fn rendered(&self) -> String {
        let mut out = String::from(&self.program);
        for a in &self.args {
            out.push(' ');
            if a.contains(' ') || a.contains('"') {
                out.push('"');
                out.push_str(&a.replace('"', "`\""));
                out.push('"');
            } else {
                out.push_str(a);
            }
        }
        out
    }
}

/// Escape a value for safe inclusion inside a single-quoted
/// PowerShell literal. PowerShell escapes a literal single quote in a
/// `'…'` string by doubling it (`''`), so any embedded `'` in a path
/// or identifier must be doubled before interpolation. Without this,
/// a single quote in the value either breaks the command's shell
/// syntax or — worse — allows arbitrary PowerShell injection.
fn ps_escape_single_quote(s: &str) -> String {
    s.replace('\'', "''")
}

/// Build the PowerShell command sequence required to apply a WDAC
/// XML policy to the local machine.
///
/// Sequence:
/// 1. `Set-CIPolicyIdInfo` — stamps the policy GUID + display name.
/// 2. `ConvertFrom-CIPolicy` — converts XML to the binary `.cip`.
/// 3. `Copy-Item` — drops the binary into
///    `%windir%\System32\CodeIntegrity\CiPolicies\Active\{PolicyGUID}.cip`.
///    The `.cip` extension is mandatory: WDAC's multiple-policy-format
///    refresh path (`PS_UpdateAndCompareCIPolicy`) only enumerates files
///    whose name matches `{PolicyGUID}.cip`, so a destination missing the
///    extension would silently no-op.
/// 4. `Invoke-CimMethod -ClassName PS_UpdateAndCompareCIPolicy` —
///    forces an immediate policy refresh.
///
/// Every caller-supplied value (xml/cip paths, policy id, display
/// name) is interpolated **only** inside single-quoted PowerShell
/// literals after being escaped via [`ps_escape_single_quote`]. The
/// `Copy-Item -Destination` argument needs `$env:windir` to expand,
/// so the destination is built with `Join-Path $env:windir '<rest>'`
/// — `$env:windir` lives outside any quote, while `policy_id_esc`
/// stays inside a single-quoted literal. This avoids the
/// double-quoted-string injection vector where a `policy_id`
/// containing `$(…)` would otherwise be evaluated.
pub fn powershell_apply_wdac_commands(
    xml_path: &Path,
    cip_path: &Path,
    policy_id: &str,
    display_name: &str,
) -> Vec<PowerShellCommand> {
    let xml = ps_escape_single_quote(&xml_path.to_string_lossy());
    let cip = ps_escape_single_quote(&cip_path.to_string_lossy());
    let policy_id_esc = ps_escape_single_quote(policy_id);
    let display_name_esc = ps_escape_single_quote(display_name);
    vec![
        PowerShellCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                format!(
                    "Set-CIPolicyIdInfo -FilePath '{}' -PolicyId '{}' -PolicyName '{}'",
                    xml, policy_id_esc, display_name_esc
                ),
            ],
        },
        PowerShellCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                format!("ConvertFrom-CIPolicy -XmlFilePath '{}' -BinaryFilePath '{}'", xml, cip),
            ],
        },
        PowerShellCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                format!(
                    "Copy-Item -Path '{}' -Destination (Join-Path $env:windir 'System32\\CodeIntegrity\\CiPolicies\\Active\\{}.cip') -Force",
                    cip, policy_id_esc
                ),
            ],
        },
        PowerShellCommand {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                "Invoke-CimMethod -Namespace root\\Microsoft\\Windows\\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update".into(),
            ],
        },
    ]
}

/// Build the PowerShell command sequence to apply an AppLocker
/// policy XML. The XML path is escaped via [`ps_escape_single_quote`]
/// before being interpolated.
pub fn powershell_apply_applocker_commands(xml_path: &Path) -> Vec<PowerShellCommand> {
    let xml = ps_escape_single_quote(&xml_path.to_string_lossy());
    vec![PowerShellCommand {
        program: "powershell.exe".into(),
        args: vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            format!("Set-AppLockerPolicy -XmlPolicy '{}' -Merge:$false", xml),
        ],
    }]
}

/// Last-applied artifact recorded by [`WdacAppControlProvider`].
/// Used by tests and by the supervisor to surface in evidence
/// records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdacApplyRecord {
    pub backend: WdacBackend,
    /// Mode the policy was applied in. Sourced from
    /// `AppControlPolicyPayload::target_mode` at apply time so
    /// `current_mode()` can faithfully report it back.
    pub mode: AppControlMode,
    pub xml: String,
    pub commands: Vec<PowerShellCommand>,
    pub applied_at: DateTime<Utc>,
}

/// Cross-platform Windows app-control provider.
///
/// On Windows it actually invokes PowerShell; on every other host it
/// records the rendered XML + command sequence and returns
/// `Ok(())` so the agent can exercise the full translation path on
/// CI.
pub struct WdacAppControlProvider {
    backend: WdacBackend,
    staging_dir: PathBuf,
    last_applied: Mutex<Option<WdacApplyRecord>>,
}

impl std::fmt::Debug for WdacAppControlProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WdacAppControlProvider")
            .field("backend", &self.backend)
            .field("staging_dir", &self.staging_dir)
            .finish()
    }
}

impl WdacAppControlProvider {
    /// Build a provider with the platform-default staging directory
    /// and `select_backend(os_build)` for backend selection.
    pub fn new(os_build: u32, staging_dir: PathBuf) -> Self {
        Self::with_backend(select_backend(os_build), staging_dir)
    }

    /// Build a provider with a caller-specified backend. Used by
    /// tests.
    pub fn with_backend(backend: WdacBackend, staging_dir: PathBuf) -> Self {
        Self {
            backend,
            staging_dir,
            last_applied: Mutex::new(None),
        }
    }

    /// Read-only snapshot of the last applied artefact.
    pub fn last_applied(&self) -> Option<WdacApplyRecord> {
        self.last_applied.lock().ok().and_then(|g| g.clone())
    }

    /// Selected backend.
    pub fn backend(&self) -> WdacBackend {
        self.backend
    }

    fn render(&self, payload: &AppControlPolicyPayload) -> (String, Vec<PowerShellCommand>) {
        let xml_path = self
            .staging_dir
            .join(format!("sda-app-control-{}.xml", payload.version));
        match self.backend {
            WdacBackend::Wdac => {
                let doc = build_wdac_document(payload);
                let xml = render_wdac_xml(&doc);
                let cip_path = self
                    .staging_dir
                    .join(format!("sda-app-control-{}.cip", payload.version));
                let cmds = powershell_apply_wdac_commands(
                    &xml_path,
                    &cip_path,
                    &doc.policy_id,
                    &doc.policy_name,
                );
                (xml, cmds)
            }
            WdacBackend::AppLocker => {
                let doc = build_applocker_document(payload);
                let xml = render_applocker_xml(&doc);
                let cmds = powershell_apply_applocker_commands(&xml_path);
                (xml, cmds)
            }
        }
    }
}

impl AppControlProvider for WdacAppControlProvider {
    fn current_mode(&self) -> Result<AppControlMode, AppControlError> {
        // Probing the live Windows policy is best-effort; on every
        // host we can only safely report the last mode the agent
        // *intended* to set, recorded at apply time on the
        // `WdacApplyRecord`.
        Ok(self
            .last_applied
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|r| r.mode))
            .unwrap_or(AppControlMode::Disabled))
    }

    fn apply_verified_policy(
        &self,
        payload: &AppControlPolicyPayload,
    ) -> Result<(), AppControlError> {
        let (xml, commands) = self.render(payload);

        #[cfg(target_os = "windows")]
        {
            // Best-effort filesystem prep + invocation. Failures
            // bubble out as `AppControlError::Backend` so the
            // EnforceController can trigger dual-control rollback.
            std::fs::create_dir_all(&self.staging_dir)
                .map_err(|e| AppControlError::Backend(format!("staging dir: {e}")))?;
            let xml_path = self
                .staging_dir
                .join(format!("sda-app-control-{}.xml", payload.version));
            std::fs::write(&xml_path, &xml)
                .map_err(|e| AppControlError::Backend(format!("write xml: {e}")))?;
            for cmd in &commands {
                let status = std::process::Command::new(&cmd.program)
                    .args(&cmd.args)
                    .status()
                    .map_err(|e| AppControlError::Backend(format!("spawn {}: {e}", cmd.program)))?;
                if !status.success() {
                    return Err(AppControlError::Backend(format!(
                        "{} exited with status {}",
                        cmd.rendered(),
                        status
                    )));
                }
            }
        }

        if let Ok(mut g) = self.last_applied.lock() {
            *g = Some(WdacApplyRecord {
                backend: self.backend,
                mode: payload.target_mode,
                xml,
                commands,
                applied_at: Utc::now(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_payload(version: u64) -> AppControlPolicyPayload {
        AppControlPolicyPayload {
            version,
            issued_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            target_mode: AppControlMode::Enforce,
            rules: vec![
                AppControlRule {
                    subject: "sha256:deadbeef".into(),
                    allow: true,
                    reason: "trusted package".into(),
                },
                AppControlRule {
                    subject: "publisher:CN=Microsoft Corporation".into(),
                    allow: true,
                    reason: "ms publisher".into(),
                },
                AppControlRule {
                    subject: "path:C\\\\Windows\\\\Temp\\\\evil.exe".into(),
                    allow: false,
                    reason: "blocked".into(),
                },
                AppControlRule {
                    subject: "weird:thing".into(),
                    allow: true,
                    reason: "unknown subject kind".into(),
                },
            ],
        }
    }

    #[test]
    fn select_backend_picks_wdac_on_modern_windows() {
        assert_eq!(select_backend(19_045), WdacBackend::Wdac);
        assert_eq!(select_backend(MIN_WDAC_WINDOWS_BUILD), WdacBackend::Wdac);
    }

    #[test]
    fn select_backend_falls_back_to_applocker_on_legacy() {
        assert_eq!(
            select_backend(MIN_WDAC_WINDOWS_BUILD - 1),
            WdacBackend::AppLocker
        );
        assert_eq!(select_backend(0), WdacBackend::AppLocker);
    }

    #[test]
    fn parse_subject_recognises_known_kinds() {
        assert_eq!(
            parse_subject("sha256:abc"),
            (SubjectKind::Sha256, "abc".into())
        );
        assert_eq!(
            parse_subject("publisher:CN=ACME"),
            (SubjectKind::PublisherCommonName, "CN=ACME".into())
        );
        assert_eq!(
            parse_subject("pfn:Foo_1.2"),
            (SubjectKind::PackageFamilyName, "Foo_1.2".into())
        );
        assert_eq!(
            parse_subject("weird:val"),
            (SubjectKind::Unknown, "weird:val".into())
        );
    }

    #[test]
    fn parse_subject_treats_unprefixed_as_sha256() {
        assert_eq!(
            parse_subject("abcdef"),
            (SubjectKind::Sha256, "abcdef".into())
        );
    }

    #[test]
    fn build_wdac_document_translates_all_rules() {
        let payload = sample_payload(7);
        let doc = build_wdac_document(&payload);
        assert_eq!(doc.version, 7);
        assert_eq!(doc.mode, AppControlMode::Enforce);
        assert_eq!(doc.rules.len(), 4);
        assert_eq!(doc.rules[0].kind, SubjectKind::Sha256);
        assert!(doc.rules[0].allow);
        assert_eq!(doc.rules[1].kind, SubjectKind::PublisherCommonName);
        assert_eq!(doc.rules[2].kind, SubjectKind::Path);
        assert!(!doc.rules[2].allow);
        assert_eq!(doc.rules[3].kind, SubjectKind::Unknown);
        assert_eq!(doc.rules[0].id, "ID_ALLOW_S256_0");
        assert_eq!(doc.rules[2].id, "ID_DENY_PATH_2");
    }

    #[test]
    fn render_wdac_xml_includes_required_sections() {
        let payload = sample_payload(3);
        let doc = build_wdac_document(&payload);
        let xml = render_wdac_xml(&doc);
        assert!(xml.starts_with(r#"<?xml version="1.0" encoding="utf-8"?>"#));
        assert!(xml.contains(r#"<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">"#));
        assert!(xml.contains("<VersionEx>10.0.0.3</VersionEx>"));
        assert!(xml.contains(POLICY_BASE_ID));
        assert!(
            xml.contains("<FriendlyName>SN360 Desktop Agent — Application Control</FriendlyName>")
        );
        assert!(xml.contains("Hash=\"deadbeef\""));
        assert!(xml.contains("Action=\"Allow\""));
        assert!(xml.contains("Action=\"Deny\""));
        assert!(xml.contains("</SiPolicy>"));
    }

    #[test]
    fn render_wdac_xml_escapes_special_chars() {
        let payload = AppControlPolicyPayload {
            version: 1,
            issued_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            target_mode: AppControlMode::Monitor,
            rules: vec![AppControlRule {
                subject: "publisher:CN=A & B \"Co\"".into(),
                allow: true,
                reason: "x<y".into(),
            }],
        };
        let xml = render_wdac_xml(&build_wdac_document(&payload));
        assert!(!xml.contains("CN=A & B \"Co\""));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;"));
        assert!(xml.contains("x&lt;y"));
    }

    #[test]
    fn build_applocker_document_drops_unsupported_subjects() {
        let payload = sample_payload(2);
        let doc = build_applocker_document(&payload);
        assert_eq!(doc.rules.len(), 2);
        assert!(doc.rules.iter().all(|r| matches!(
            r.kind,
            SubjectKind::Sha256 | SubjectKind::PublisherCommonName
        )));
        assert_eq!(doc.dropped_subjects.len(), 2);
    }

    #[test]
    fn render_applocker_xml_uses_audit_only_for_monitor() {
        let mut payload = sample_payload(1);
        payload.target_mode = AppControlMode::Monitor;
        let doc = build_applocker_document(&payload);
        let xml = render_applocker_xml(&doc);
        assert!(xml.contains("EnforcementMode=\"AuditOnly\""));
    }

    #[test]
    fn render_applocker_xml_uses_enabled_for_enforce() {
        let payload = sample_payload(1);
        let doc = build_applocker_document(&payload);
        let xml = render_applocker_xml(&doc);
        assert!(xml.contains("EnforcementMode=\"Enabled\""));
        assert!(xml.contains("<FileHashRule"));
        assert!(xml.contains("<FilePublisherRule"));
    }

    #[test]
    fn powershell_apply_wdac_commands_emits_required_cmdlets() {
        let xml = PathBuf::from("/tmp/policy.xml");
        let cip = PathBuf::from("/tmp/policy.cip");
        let cmds = powershell_apply_wdac_commands(&xml, &cip, "policy-1", "Test Policy");
        assert_eq!(cmds.len(), 4);
        assert_eq!(cmds[0].program, "powershell.exe");
        let joined: String = cmds
            .iter()
            .flat_map(|c| c.args.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("Set-CIPolicyIdInfo"));
        assert!(joined.contains("ConvertFrom-CIPolicy"));
        assert!(joined.contains("Copy-Item"));
        assert!(joined.contains("PS_UpdateAndCompareCIPolicy"));
    }

    #[test]
    fn powershell_apply_applocker_commands_emits_set_applockerpolicy() {
        let cmds = powershell_apply_applocker_commands(&PathBuf::from("/tmp/al.xml"));
        assert_eq!(cmds.len(), 1);
        let argline = cmds[0].args.last().unwrap();
        assert!(argline.contains("Set-AppLockerPolicy"));
        assert!(argline.contains("/tmp/al.xml"));
        assert!(argline.contains("-Merge:$false"));
    }

    #[test]
    fn powershell_command_rendered_quotes_spaces() {
        let cmd = PowerShellCommand {
            program: "powershell.exe".into(),
            args: vec!["-Command".into(), "echo hello world".into()],
        };
        let line = cmd.rendered();
        assert!(line.contains('"'));
        assert!(line.contains("echo hello world"));
    }

    #[test]
    fn provider_records_apply_artefact_on_non_windows() {
        let provider = WdacAppControlProvider::with_backend(
            WdacBackend::Wdac,
            std::env::temp_dir().join("sda-wdac-test"),
        );
        let payload = sample_payload(11);
        provider.apply_verified_policy(&payload).expect("apply ok");
        let record = provider.last_applied().expect("record");
        assert_eq!(record.backend, WdacBackend::Wdac);
        assert!(record.xml.contains("<SiPolicy"));
        assert!(!record.commands.is_empty());
    }

    #[test]
    fn provider_records_applocker_when_backend_is_applocker() {
        let provider = WdacAppControlProvider::with_backend(
            WdacBackend::AppLocker,
            std::env::temp_dir().join("sda-wdac-test"),
        );
        let payload = sample_payload(12);
        provider.apply_verified_policy(&payload).expect("apply ok");
        let record = provider.last_applied().expect("record");
        assert_eq!(record.backend, WdacBackend::AppLocker);
        assert!(record.xml.contains("<AppLockerPolicy"));
        assert_eq!(record.commands.len(), 1);
    }

    #[test]
    fn provider_current_mode_starts_disabled() {
        let provider = WdacAppControlProvider::with_backend(
            WdacBackend::Wdac,
            std::env::temp_dir().join("sda-wdac-test"),
        );
        assert_eq!(provider.current_mode().unwrap(), AppControlMode::Disabled);
    }

    #[test]
    fn provider_current_mode_reflects_applied_payload_target_mode() {
        let provider = WdacAppControlProvider::with_backend(
            WdacBackend::Wdac,
            std::env::temp_dir().join("sda-wdac-test"),
        );
        let mut payload = sample_payload(21);
        payload.target_mode = AppControlMode::Enforce;
        provider.apply_verified_policy(&payload).expect("apply ok");
        assert_eq!(provider.current_mode().unwrap(), AppControlMode::Enforce);

        let mut payload2 = sample_payload(22);
        payload2.target_mode = AppControlMode::Monitor;
        provider.apply_verified_policy(&payload2).expect("apply ok");
        assert_eq!(provider.current_mode().unwrap(), AppControlMode::Monitor);
    }

    #[test]
    fn ps_escape_single_quote_doubles_embedded_quotes() {
        assert_eq!(ps_escape_single_quote("plain"), "plain");
        assert_eq!(ps_escape_single_quote("ken's path"), "ken''s path");
        assert_eq!(ps_escape_single_quote("a'b'c"), "a''b''c");
    }

    #[test]
    fn powershell_apply_wdac_commands_escapes_single_quotes_in_paths() {
        // A path containing a literal single quote must not break the
        // single-quoted PowerShell literal. The escaped value should
        // appear in the rendered argument with doubled quotes.
        let xml = PathBuf::from("/tmp/ken's policy.xml");
        let cip = PathBuf::from("/tmp/o'reilly.cip");
        let cmds = powershell_apply_wdac_commands(&xml, &cip, "id-with-'-quote", "Display 'Name'");
        let joined: String = cmds
            .iter()
            .flat_map(|c| c.args.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        // No bare unescaped quote from the inputs leaks through.
        assert!(joined.contains("ken''s policy.xml"));
        assert!(joined.contains("o''reilly.cip"));
        assert!(joined.contains("id-with-''-quote"));
        assert!(joined.contains("Display ''Name''"));
        // The literal pre-escape forms must NOT appear, otherwise the
        // single-quoted literal would be broken by the embedded quote.
        assert!(!joined.contains("ken's policy.xml"));
        assert!(!joined.contains("o'reilly.cip"));
    }

    #[test]
    fn powershell_apply_applocker_commands_escapes_single_quotes_in_paths() {
        let cmds = powershell_apply_applocker_commands(&PathBuf::from("/tmp/ken's al.xml"));
        let argline = cmds[0].args.last().unwrap();
        assert!(argline.contains("ken''s al.xml"));
        assert!(!argline.contains("ken's al.xml"));
    }

    #[test]
    fn powershell_apply_wdac_commands_neutralises_policy_id_subexpression() {
        // A `policy_id` that tries to smuggle a PowerShell
        // sub-expression must end up wrapped in a single-quoted
        // literal in every command — including the `Copy-Item`
        // destination, which previously used a double-quoted string
        // (where `$(…)` would be evaluated).
        let xml = PathBuf::from("/tmp/policy.xml");
        let cip = PathBuf::from("/tmp/policy.cip");
        let evil_id = "abc$(Invoke-Expression 'malicious')def";
        let cmds = powershell_apply_wdac_commands(&xml, &cip, evil_id, "Test");

        let copy_item_arg = cmds[2].args.last().expect("Copy-Item -Command arg");
        // Destination is now built via Join-Path with the policy id
        // inside a single-quoted literal, so no double-quoted PS
        // string is emitted at all.
        assert!(
            !copy_item_arg.contains('"'),
            "unexpected double quote in: {copy_item_arg}"
        );
        assert!(
            copy_item_arg
                .contains("Join-Path $env:windir 'System32\\CodeIntegrity\\CiPolicies\\Active\\"),
            "destination should use Join-Path with single-quoted tail: {copy_item_arg}"
        );
        // The literal `$(...)` must appear *inside* a single-quoted
        // literal — i.e. preceded somewhere on the line by an opening
        // single quote and followed by a closing one — so PowerShell
        // treats it as a string, not a sub-expression. The literal
        // must also end with `.cip'` so WDAC's refresh path enumerates
        // the dropped file.
        assert!(
            copy_item_arg.contains("'System32\\CodeIntegrity\\CiPolicies\\Active\\abc$(Invoke-Expression ''malicious'')def.cip'"),
            "policy_id sub-expression must be inside a single-quoted literal ending in .cip: {copy_item_arg}"
        );

        // And every other rendered argument across all four commands
        // must also keep the sub-expression bytes inside a
        // single-quoted literal — never as a bare token.
        let joined: String = cmds
            .iter()
            .flat_map(|c| c.args.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        // Embedded single quotes inside the policy id are doubled by
        // ps_escape_single_quote, so the `'malicious'` portion is
        // rendered as `''malicious''`.
        assert!(joined.contains("abc$(Invoke-Expression ''malicious'')def"));
        // Pre-escape form must NOT survive — that would mean the
        // outer single-quoted literal is broken.
        assert!(!joined.contains("abc$(Invoke-Expression 'malicious')def.cip"));
    }

    #[test]
    fn powershell_apply_wdac_commands_destination_ends_in_cip_extension() {
        // WDAC's multiple-policy-format refresh path
        // (`PS_UpdateAndCompareCIPolicy`) only enumerates files named
        // `{PolicyGUID}.cip` inside `Active\`. The Copy-Item
        // destination must therefore append `.cip` to the policy id
        // — the *destination filename*, not the source file extension,
        // is what governs activation.
        let xml = PathBuf::from("/tmp/policy.xml");
        let cip = PathBuf::from("/tmp/policy.cip");
        let cmds = powershell_apply_wdac_commands(&xml, &cip, "policy-guid-1", "Test");
        let copy_item_arg = cmds[2].args.last().expect("Copy-Item -Command arg");
        assert!(
            copy_item_arg.contains("Active\\policy-guid-1.cip'"),
            "destination must end in `{{policy_id}}.cip`: {copy_item_arg}"
        );
        // And the destination single-quoted literal must close right
        // after the .cip — i.e. nothing else got appended after the
        // extension that would form a different filename.
        assert!(
            copy_item_arg.contains("Active\\policy-guid-1.cip') -Force"),
            "destination single-quoted literal must close immediately after .cip: {copy_item_arg}"
        );
    }

    #[test]
    fn provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WdacAppControlProvider>();
    }
}
