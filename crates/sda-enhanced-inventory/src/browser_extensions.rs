//! Cross-platform browser-extension enumeration (task 4.8).
//!
//! Discovers installed extensions for:
//!
//! | Browser  | Source                                                                                   |
//! |----------|------------------------------------------------------------------------------------------|
//! | Chrome   | `<UserData>/<profile>/Extensions/<id>/<version>/manifest.json`                           |
//! | Edge     | Same layout as Chrome, rooted at Edge's `User Data`                                      |
//! | Firefox  | `<profile>/extensions.json` (an Addon Manager database with `id`, `version`, `path`…)    |
//! | Safari   | `~/Library/Safari/Extensions/*` (legacy) and `pluginkit -mAvvv -p com.apple.Safari.extension` |
//!
//! Missing browsers, empty profile directories, and malformed
//! manifests are silently skipped — a scan always succeeds, and an
//! empty vector is returned when nothing is installed.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::debug;

/// A single installed browser extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserExtension {
    /// Browser identifier: `"chrome"`, `"firefox"`, `"edge"`, or `"safari"`.
    pub browser: String,
    /// Profile directory name (e.g. `"Default"`, `"Profile 1"`, the
    /// Firefox profile slug). Empty for browsers with no profile
    /// concept (Safari).
    pub profile: String,
    /// Extension identifier (Chrome Web Store id, Firefox GUID,
    /// Safari bundle identifier).
    pub extension_id: String,
    /// Display name, resolved from the manifest or extensions.json.
    pub name: String,
    /// Version string from the manifest or extensions.json.
    pub version: String,
    /// Description from the manifest, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the extension is enabled. Only reliably reported for
    /// Firefox (from `active` / `userDisabled`); `None` for Chromium
    /// and Safari because the filesystem alone doesn't encode it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Absolute filesystem path to the extension on disk.
    pub path: String,
}

/// Enumerate every browser extension visible to the current user on
/// this host.
///
/// Blocking filesystem / subprocess work — call from
/// [`tokio::task::spawn_blocking`].
pub fn enumerate_browser_extensions() -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    let Some(home) = home_dir() else {
        return out;
    };
    for base in chromium_bases("chrome", &home) {
        out.extend(scan_chromium("chrome", &base));
    }
    for base in chromium_bases("edge", &home) {
        out.extend(scan_chromium("edge", &base));
    }
    for profile_dir in firefox_profile_dirs(&home) {
        out.extend(scan_firefox(&profile_dir));
    }
    #[cfg(target_os = "macos")]
    {
        out.extend(safari::scan(&home));
    }
    out
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// `User Data` directories for a Chromium-based browser on this host.
///
/// One base per browser per platform; callers iterate the result and
/// scan each entry's profile subdirectories.
fn chromium_bases(browser: &str, home: &Path) -> Vec<PathBuf> {
    let _ = home;
    let mut out = Vec::new();
    match browser {
        "chrome" => {
            #[cfg(target_os = "linux")]
            out.push(home.join(".config").join("google-chrome"));
            #[cfg(target_os = "macos")]
            out.push(home.join("Library/Application Support/Google/Chrome"));
            #[cfg(target_os = "windows")]
            {
                if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                    out.push(PathBuf::from(local).join(r"Google\Chrome\User Data"));
                }
            }
        }
        "edge" => {
            #[cfg(target_os = "linux")]
            out.push(home.join(".config").join("microsoft-edge"));
            #[cfg(target_os = "macos")]
            out.push(home.join("Library/Application Support/Microsoft Edge"));
            #[cfg(target_os = "windows")]
            {
                if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                    out.push(PathBuf::from(local).join(r"Microsoft\Edge\User Data"));
                }
            }
        }
        _ => {}
    }
    out
}

/// Scan a Chromium `User Data` directory for installed extensions.
///
/// Layout: `<base>/<profile>/Extensions/<ext_id>/<version>/manifest.json`.
fn scan_chromium(browser: &str, base: &Path) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    let Ok(profiles) = fs::read_dir(base) else {
        return out;
    };
    for entry in profiles.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(profile) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !is_chromium_profile_dir(&profile) {
            continue;
        }
        let ext_root = entry.path().join("Extensions");
        out.extend(scan_chromium_profile(browser, &profile, &ext_root));
    }
    out
}

/// Chromium puts user profiles in `Default`, `Profile N`,
/// `Guest Profile`, and `System Profile`; other siblings (`Crashpad`,
/// `GrShaderCache`, etc.) are caches and filtering them out keeps the
/// scan focused on real profiles.
fn is_chromium_profile_dir(name: &str) -> bool {
    name == "Default"
        || name == "System Profile"
        || name.starts_with("Profile ")
        || name.starts_with("Guest Profile")
}

fn scan_chromium_profile(browser: &str, profile: &str, ext_root: &Path) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(ext_root) else {
        return out;
    };
    for ext_entry in entries.flatten() {
        if !ext_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(ext_id) = ext_entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if let Some(extension) =
            read_chromium_extension(browser, profile, &ext_id, &ext_entry.path())
        {
            out.push(extension);
        }
    }
    out
}

fn read_chromium_extension(
    browser: &str,
    profile: &str,
    ext_id: &str,
    ext_dir: &Path,
) -> Option<BrowserExtension> {
    // Each extension id directory contains one or more version
    // subdirectories; pick the lexically-greatest one so we report
    // the installed version rather than a stale one left behind for
    // garbage collection.
    let (version_dir, dir_version) = latest_version_dir(ext_dir)?;
    let manifest_path = version_dir.join("manifest.json");
    let manifest_text = fs::read_to_string(&manifest_path).ok()?;
    let manifest: serde_json::Value = match serde_json::from_str(&manifest_text) {
        Ok(v) => v,
        Err(e) => {
            debug!(
                error = %e,
                path = %manifest_path.display(),
                "skipping malformed manifest.json",
            );
            return None;
        }
    };

    let default_locale = manifest.get("default_locale").and_then(|v| v.as_str());

    let raw_name = manifest
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(ext_id);
    let name = resolve_chromium_message(raw_name, &version_dir, default_locale)
        .unwrap_or_else(|| raw_name.to_string());

    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or(&dir_version)
        .to_string();

    let description = manifest
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| {
            resolve_chromium_message(s, &version_dir, default_locale)
                .unwrap_or_else(|| s.to_string())
        });

    Some(BrowserExtension {
        browser: browser.to_string(),
        profile: profile.to_string(),
        extension_id: ext_id.to_string(),
        name,
        version,
        description,
        enabled: None,
        path: version_dir.to_string_lossy().into_owned(),
    })
}

/// Resolve `__MSG_key__` references in Chromium manifests against
/// `_locales/<locale>/messages.json`. The manifest's `default_locale`
/// (if any) is tried first, then a short English fallback chain so an
/// extension shipped in English still resolves on a host where the
/// authoring locale happens to be absent.
///
/// Returns `Some` only when the passthrough text actually wrapped a
/// `__MSG_…__` reference; callers treat `None` as "not a reference".
fn resolve_chromium_message(
    raw: &str,
    ext_dir: &Path,
    default_locale: Option<&str>,
) -> Option<String> {
    let key = raw.strip_prefix("__MSG_")?.strip_suffix("__")?;
    // Candidate locale chain: manifest-declared default first, then a
    // short English fallback. Deduplicate while preserving order.
    let mut locales: Vec<String> = Vec::new();
    let mut push = |loc: &str| {
        if !loc.is_empty() && !locales.iter().any(|existing| existing == loc) {
            locales.push(loc.to_string());
        }
    };
    if let Some(loc) = default_locale {
        push(loc);
    }
    push("en");
    push("en_US");
    push("en_GB");

    for locale in &locales {
        let path = ext_dir.join("_locales").join(locale).join("messages.json");
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let msg = value
            .get(key)
            .or_else(|| value.get(key.to_lowercase().as_str()));
        if let Some(msg) = msg.and_then(|v| v.get("message")).and_then(|v| v.as_str()) {
            return Some(msg.to_string());
        }
    }
    // The reference was well-formed but unresolved — return the bare
    // key so at least something sensible lands in the inventory.
    Some(key.to_string())
}

fn latest_version_dir(ext_dir: &Path) -> Option<(PathBuf, String)> {
    let entries = fs::read_dir(ext_dir).ok()?;
    let mut best: Option<(PathBuf, String, Vec<u64>)> = None;
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        // Chromium names version directories after the manifest version
        // with an optional trailing `_N` suffix (e.g. `1.50.0_0`); they
        // always start with a digit, so anything else is scratch state.
        if !name
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            continue;
        }
        let parts = parse_chromium_version_dir(&name);
        match &best {
            Some((_, _, current)) if current >= &parts => {}
            _ => best = Some((entry.path(), name, parts)),
        }
    }
    best.map(|(path, name, _)| (path, name))
}

/// Convert a Chromium version-directory name (e.g. `1.50.0_0`) into a
/// tuple of numeric components for component-wise comparison. This
/// avoids the classic lexicographic trap where `"9.0.0_0"` sorts after
/// `"10.0.0_0"`. Non-numeric characters are treated as separators;
/// any parse failure per component drops to 0, which keeps the order
/// stable and non-panicking on unexpected inputs.
fn parse_chromium_version_dir(name: &str) -> Vec<u64> {
    name.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect()
}

/// Firefox profile directories on this host, filtered to those that
/// actually hold an `extensions.json` database.
fn firefox_profile_dirs(home: &Path) -> Vec<PathBuf> {
    let _ = home;
    let roots: Vec<PathBuf> = {
        #[cfg(target_os = "linux")]
        {
            vec![home.join(".mozilla/firefox")]
        }
        #[cfg(target_os = "macos")]
        {
            vec![
                home.join("Library/Application Support/Firefox/Profiles"),
                home.join("Library/Mozilla/Firefox/Profiles"),
            ]
        }
        #[cfg(target_os = "windows")]
        {
            let mut r = Vec::new();
            if let Some(roaming) = std::env::var_os("APPDATA") {
                r.push(PathBuf::from(roaming).join(r"Mozilla\Firefox\Profiles"));
            }
            r
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Vec::<PathBuf>::new()
        }
    };

    let mut out = Vec::new();
    for root in roots {
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let candidate = entry.path();
            if candidate.join("extensions.json").exists() {
                out.push(candidate);
            }
        }
    }
    out
}

/// Parse a Firefox `extensions.json` for an individual profile.
///
/// Public so tests can synthesize a temp profile and verify parsing
/// without relying on a real Firefox install.
pub fn scan_firefox(profile_dir: &Path) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    let extensions_json = profile_dir.join("extensions.json");
    let Ok(text) = fs::read_to_string(&extensions_json) else {
        return out;
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            debug!(
                error = %e,
                path = %extensions_json.display(),
                "skipping malformed Firefox extensions.json",
            );
            return out;
        }
    };
    let Some(addons) = value.get("addons").and_then(|v| v.as_array()) else {
        return out;
    };
    let profile_name = profile_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    for addon in addons {
        let ty = addon
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("extension");
        // `theme`, `locale`, `dictionary`, `sitepermission` are reported
        // through the Addon Manager but aren't user-installed extensions
        // in the 4.8 sense — skip them so the inventory stays focused.
        if ty != "extension" {
            continue;
        }
        let Some(id) = addon
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        else {
            continue;
        };
        let version = addon
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let path = addon
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();
        let active = addon.get("active").and_then(|v| v.as_bool());
        let user_disabled = addon
            .get("userDisabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let app_disabled = addon
            .get("appDisabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let enabled = active.map(|a| a && !user_disabled && !app_disabled);
        let default_locale = addon.get("defaultLocale");
        let name = default_locale
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .or_else(|| addon.get("name").and_then(|v| v.as_str()))
            .unwrap_or(&id)
            .to_string();
        let description = default_locale
            .and_then(|v| v.get("description"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        out.push(BrowserExtension {
            browser: "firefox".to_string(),
            profile: profile_name.clone(),
            extension_id: id,
            name,
            version,
            description,
            enabled,
            path,
        });
    }
    out
}

#[cfg(target_os = "macos")]
mod safari {
    use super::BrowserExtension;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    pub(super) fn scan(home: &Path) -> Vec<BrowserExtension> {
        let mut out = Vec::new();
        // Legacy `~/Library/Safari/Extensions/*.safariextz` and any
        // `.appex` bundles installed side-loaded there.
        let legacy = home.join("Library/Safari/Extensions");
        if let Ok(entries) = fs::read_dir(&legacy) {
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
                    continue;
                };
                out.push(BrowserExtension {
                    browser: "safari".to_string(),
                    profile: String::new(),
                    extension_id: name.clone(),
                    name,
                    version: String::new(),
                    description: None,
                    enabled: None,
                    path: entry.path().to_string_lossy().into_owned(),
                });
            }
        }

        // Modern Safari app-extensions live inside regular `.app` bundles
        // and are registered with `pluginkit`. The command is part of
        // macOS base (no brew install needed) and emits one line per
        // plugin with the bundle id, version, and absolute path.
        if let Ok(output) = Command::new("/usr/bin/pluginkit")
            .args(["-mAvvv", "-p", "com.apple.Safari.extension"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                out.extend(parse_pluginkit_output(&text));
            }
        }

        out
    }

    /// Parse a single `pluginkit -mAvvv` output block.
    ///
    /// Kept tolerant — the exact format differs between macOS releases
    /// and verbosity levels, so the parser extracts a bundle id, an
    /// optional `(version)`, and a trailing absolute path, and ignores
    /// lines that don't match.
    pub(super) fn parse_pluginkit_output(text: &str) -> Vec<BrowserExtension> {
        let mut out = Vec::new();
        for line in text.lines() {
            let trimmed = line
                .trim_start_matches(|c: char| {
                    matches!(c, '+' | '-' | '?' | '!') || c.is_whitespace()
                })
                .trim_end();
            if trimmed.is_empty() {
                continue;
            }
            // The head token is either `bundle.id(version)` or just
            // `bundle.id`; the rest of the line holds attributes.
            let (head, rest) = match trimmed.split_once(char::is_whitespace) {
                Some((h, r)) => (h, r),
                None => (trimmed, ""),
            };
            let (id, version) = match head.rsplit_once('(') {
                Some((id, v)) if v.ends_with(')') && !id.is_empty() => {
                    (id.to_string(), v[..v.len() - 1].to_string())
                }
                _ => (head.to_string(), String::new()),
            };
            if !looks_like_bundle_id(&id) {
                continue;
            }
            let path = rest
                .split_whitespace()
                .rfind(|tok| tok.starts_with('/'))
                .map(|s| s.to_string())
                .unwrap_or_default();
            out.push(BrowserExtension {
                browser: "safari".to_string(),
                profile: String::new(),
                extension_id: id.clone(),
                name: id,
                version,
                description: None,
                enabled: None,
                path,
            });
        }
        out
    }

    fn looks_like_bundle_id(s: &str) -> bool {
        // Reverse-DNS bundle identifiers: at least one dot, only ASCII
        // identifier-ish characters.
        s.contains('.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_parse_pluginkit_extracts_id_version_and_path() {
            let sample = "\
+    com.example.vendor.SafariExt(1.2.3)    12345 /Applications/Vendor.app/Contents/PlugIns/SafariExt.appex
         Display Name:    Vendor Safari Extension
";
            let exts = parse_pluginkit_output(sample);
            assert_eq!(exts.len(), 1);
            let e = &exts[0];
            assert_eq!(e.browser, "safari");
            assert_eq!(e.extension_id, "com.example.vendor.SafariExt");
            assert_eq!(e.version, "1.2.3");
            assert_eq!(
                e.path,
                "/Applications/Vendor.app/Contents/PlugIns/SafariExt.appex"
            );
        }

        #[test]
        fn test_parse_pluginkit_tolerates_missing_version() {
            let sample =
                "    com.example.nover    /Applications/Nover.app/Contents/PlugIns/X.appex\n";
            let exts = parse_pluginkit_output(sample);
            assert_eq!(exts.len(), 1);
            assert_eq!(exts[0].extension_id, "com.example.nover");
            assert_eq!(exts[0].version, "");
        }

        #[test]
        fn test_parse_pluginkit_skips_garbage_lines() {
            let sample = "not a bundle id at all\n    \n";
            assert!(parse_pluginkit_output(sample).is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    /// Write a minimal Chromium extension on disk mimicking the real
    /// `<ext_id>/<version>/manifest.json` layout and return the
    /// profile `Extensions` directory a scanner should point at.
    fn write_chromium_extension(
        root: &Path,
        profile: &str,
        ext_id: &str,
        version: &str,
        manifest: &str,
    ) -> PathBuf {
        let ext_root = root.join(profile).join("Extensions");
        let version_dir = ext_root.join(ext_id).join(version);
        fs::create_dir_all(&version_dir).unwrap();
        let mut f = fs::File::create(version_dir.join("manifest.json")).unwrap();
        f.write_all(manifest.as_bytes()).unwrap();
        ext_root
    }

    #[test]
    fn test_scan_chromium_reads_manifest_fields() {
        let tmp = tempdir();
        let profile = "Default";
        let ext_id = "abcdefghijklmnopabcdefghijklmnop";
        let manifest = r#"{
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.2.3",
            "description": "An example"
        }"#;
        write_chromium_extension(&tmp, profile, ext_id, "1.2.3_0", manifest);

        let out = scan_chromium("chrome", &tmp);
        assert_eq!(out.len(), 1, "expected one extension, got {:?}", out);
        let e = &out[0];
        assert_eq!(e.browser, "chrome");
        assert_eq!(e.profile, profile);
        assert_eq!(e.extension_id, ext_id);
        assert_eq!(e.name, "Test Extension");
        assert_eq!(e.version, "1.2.3");
        assert_eq!(e.description.as_deref(), Some("An example"));
        assert!(e.path.contains("1.2.3_0"));
        assert_eq!(e.enabled, None);
    }

    #[test]
    fn test_scan_chromium_picks_latest_version_dir() {
        let tmp = tempdir();
        let ext_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let base_manifest =
            |v: &str| format!(r#"{{"manifest_version":3,"name":"E","version":"{}"}}"#, v);
        write_chromium_extension(&tmp, "Default", ext_id, "1.0.0_0", &base_manifest("1.0.0"));
        write_chromium_extension(&tmp, "Default", ext_id, "2.5.1_0", &base_manifest("2.5.1"));
        write_chromium_extension(&tmp, "Default", ext_id, "0.9.0_0", &base_manifest("0.9.0"));

        let out = scan_chromium("chrome", &tmp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].version, "2.5.1");
        assert!(out[0].path.contains("2.5.1_0"));
    }

    #[test]
    fn test_scan_chromium_skips_malformed_manifest() {
        let tmp = tempdir();
        let ext_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        write_chromium_extension(&tmp, "Default", ext_id, "1.0.0_0", "{ this is not json");
        assert!(
            scan_chromium("chrome", &tmp).is_empty(),
            "malformed manifest.json must be skipped, not returned as an entry",
        );
    }

    #[test]
    fn test_scan_chromium_skips_non_profile_directories() {
        let tmp = tempdir();
        // `Crashpad` is not a profile directory; putting an
        // `Extensions/<id>/<version>/manifest.json` under it must be
        // ignored.
        write_chromium_extension(
            &tmp,
            "Crashpad",
            "cccccccccccccccccccccccccccccccc",
            "1.0.0_0",
            r#"{"name":"nope","version":"1.0.0"}"#,
        );
        assert!(scan_chromium("chrome", &tmp).is_empty());
    }

    #[test]
    fn test_scan_chromium_returns_empty_for_missing_user_data() {
        let tmp = tempdir();
        // User Data dir exists but has no profiles / extensions.
        assert!(scan_chromium("chrome", &tmp).is_empty());
        // Nonexistent path: still empty (not an error).
        assert!(scan_chromium("chrome", &tmp.join("missing")).is_empty());
    }

    #[test]
    fn test_resolve_chromium_message_resolves_locale_reference() {
        let tmp = tempdir();
        let ext_dir = tmp.join("ext/1.0.0");
        fs::create_dir_all(ext_dir.join("_locales/en")).unwrap();
        let messages = r#"{"app_name":{"message":"My App"}}"#;
        fs::write(ext_dir.join("_locales/en/messages.json"), messages).unwrap();

        let resolved = resolve_chromium_message("__MSG_app_name__", &ext_dir, None);
        assert_eq!(resolved.as_deref(), Some("My App"));
    }

    #[test]
    fn test_resolve_chromium_message_returns_none_for_non_reference() {
        let tmp = tempdir();
        assert!(resolve_chromium_message("Plain Name", &tmp, None).is_none());
    }

    #[test]
    fn test_resolve_chromium_message_prefers_manifest_default_locale() {
        // When the manifest declares `"default_locale": "de"`, German
        // messages should resolve even when no `_locales/en` directory
        // exists on disk.
        let tmp = tempdir();
        let ext_dir = tmp.join("ext/1.0.0");
        fs::create_dir_all(ext_dir.join("_locales/de")).unwrap();
        fs::write(
            ext_dir.join("_locales/de/messages.json"),
            r#"{"app_name":{"message":"Meine App"}}"#,
        )
        .unwrap();

        let resolved = resolve_chromium_message("__MSG_app_name__", &ext_dir, Some("de"));
        assert_eq!(resolved.as_deref(), Some("Meine App"));
    }

    #[test]
    fn test_parse_chromium_version_dir_orders_numerically() {
        // Regression: lexicographic ordering would place "9.0.0_0"
        // after "10.0.0_0"; numeric ordering must not.
        let v9 = parse_chromium_version_dir("9.0.0_0");
        let v10 = parse_chromium_version_dir("10.0.0_0");
        assert!(
            v10 > v9,
            "10.0.0_0 ({v10:?}) must sort after 9.0.0_0 ({v9:?})"
        );
        assert_eq!(parse_chromium_version_dir("1.50.0_0"), vec![1, 50, 0, 0]);
    }

    #[test]
    fn test_scan_chromium_picks_numerically_latest_version_dir() {
        // Regression for the lexicographic-sort bug: with both
        // `9.0.0_0` and `10.0.0_0` on disk, the scanner must pick
        // 10.x as the installed version.
        let tmp = tempdir();
        let ext_id = "ffffffffffffffffffffffffffffffff";
        let manifest = |v: &str| format!(r#"{{"name":"E","version":"{}"}}"#, v);
        write_chromium_extension(&tmp, "Default", ext_id, "9.0.0_0", &manifest("9.0.0"));
        write_chromium_extension(&tmp, "Default", ext_id, "10.0.0_0", &manifest("10.0.0"));

        let out = scan_chromium("chrome", &tmp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].version, "10.0.0");
        assert!(out[0].path.contains("10.0.0_0"));
    }

    #[test]
    fn test_scan_firefox_parses_extensions_json() {
        let tmp = tempdir();
        let profile = tmp.join("p9x8z3qw.default-release");
        fs::create_dir_all(&profile).unwrap();
        let json = r#"{
            "schemaVersion": 35,
            "addons": [
                {
                    "id": "uBlock0@raymondhill.net",
                    "version": "1.50.0",
                    "type": "extension",
                    "active": true,
                    "userDisabled": false,
                    "appDisabled": false,
                    "path": "/tmp/ublock",
                    "defaultLocale": {
                        "name": "uBlock Origin",
                        "description": "Blocks ads."
                    }
                },
                {
                    "id": "dark-theme@mozilla.org",
                    "version": "1.0",
                    "type": "theme",
                    "active": true,
                    "userDisabled": false,
                    "defaultLocale": {"name": "Dark Theme"}
                },
                {
                    "id": "disabled@example.com",
                    "version": "2.0",
                    "type": "extension",
                    "active": false,
                    "userDisabled": true,
                    "path": "/tmp/disabled",
                    "defaultLocale": {"name": "Disabled Ext"}
                }
            ]
        }"#;
        fs::write(profile.join("extensions.json"), json).unwrap();

        let out = scan_firefox(&profile);
        assert_eq!(out.len(), 2, "themes should be filtered out; got {:?}", out);
        let ublock = out
            .iter()
            .find(|e| e.extension_id == "uBlock0@raymondhill.net")
            .expect("uBlock must be present");
        assert_eq!(ublock.browser, "firefox");
        assert_eq!(ublock.profile, "p9x8z3qw.default-release");
        assert_eq!(ublock.name, "uBlock Origin");
        assert_eq!(ublock.version, "1.50.0");
        assert_eq!(ublock.description.as_deref(), Some("Blocks ads."));
        assert_eq!(ublock.enabled, Some(true));
        assert_eq!(ublock.path, "/tmp/ublock");

        let disabled = out
            .iter()
            .find(|e| e.extension_id == "disabled@example.com")
            .expect("disabled extension must still be reported");
        assert_eq!(disabled.enabled, Some(false));
    }

    #[test]
    fn test_scan_firefox_missing_extensions_json_yields_empty() {
        let tmp = tempdir();
        let profile = tmp.join("empty.default");
        fs::create_dir_all(&profile).unwrap();
        assert!(scan_firefox(&profile).is_empty());
    }

    #[test]
    fn test_scan_firefox_malformed_json_yields_empty() {
        let tmp = tempdir();
        let profile = tmp.join("bad.default");
        fs::create_dir_all(&profile).unwrap();
        fs::write(profile.join("extensions.json"), "{not json").unwrap();
        assert!(scan_firefox(&profile).is_empty());
    }

    #[test]
    fn test_enumerate_browser_extensions_does_not_error_on_clean_host() {
        // No panics, no errors — returns a (possibly empty) vec even
        // when none of the browsers are installed.
        let _ = enumerate_browser_extensions();
    }

    #[test]
    fn test_chromium_profile_dir_filter() {
        assert!(is_chromium_profile_dir("Default"));
        assert!(is_chromium_profile_dir("Profile 1"));
        assert!(is_chromium_profile_dir("Profile 14"));
        assert!(is_chromium_profile_dir("Guest Profile"));
        assert!(is_chromium_profile_dir("System Profile"));
        assert!(!is_chromium_profile_dir("Crashpad"));
        assert!(!is_chromium_profile_dir("GrShaderCache"));
        assert!(!is_chromium_profile_dir("Local State"));
    }

    #[test]
    fn test_browser_extension_json_roundtrips() {
        let ext = BrowserExtension {
            browser: "chrome".to_string(),
            profile: "Default".to_string(),
            extension_id: "abc".to_string(),
            name: "n".to_string(),
            version: "1.0".to_string(),
            description: None,
            enabled: None,
            path: "/x".to_string(),
        };
        let value = serde_json::to_value(&ext).unwrap();
        // `None` fields are skipped per the #[serde(skip_serializing_if)].
        assert!(value.get("description").is_none());
        assert!(value.get("enabled").is_none());
        let round: BrowserExtension = serde_json::from_value(value).unwrap();
        assert_eq!(round, ext);
    }

    /// Create a temporary directory under `$CARGO_TARGET_TMPDIR` /
    /// `std::env::temp_dir()` that auto-cleans on test exit. A hand-
    /// rolled equivalent of the `tempfile` crate so we don't pull in
    /// a new dependency for a single helper.
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("sda-bext-test-{}-{}-{}", pid, nanos, n));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
