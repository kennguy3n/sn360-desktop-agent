//! Integration tests that exercise the browser-extensions scanner
//! end-to-end against synthetic on-disk layouts.

use std::fs;
use std::path::{Path, PathBuf};

use sda_enhanced_inventory::browser_extensions::{
    enumerate_browser_extensions, scan_firefox, BrowserExtension,
};

/// Create a unique scratch directory under `std::env::temp_dir()`.
/// Hand-rolled to avoid pulling the `tempfile` crate in just for one
/// helper — the test itself cleans up via `Drop` on an owned guard.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("sda-bext-it-{tag}-{pid}-{nanos}-{n}"));
        fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_chrome_extension(
    home: &Path,
    profile: &str,
    ext_id: &str,
    version_dir: &str,
    manifest: &str,
) {
    #[cfg(target_os = "linux")]
    let user_data = home.join(".config/google-chrome");
    #[cfg(target_os = "macos")]
    let user_data = home.join("Library/Application Support/Google/Chrome");
    #[cfg(target_os = "windows")]
    let user_data = home.join(r"AppData\Local\Google\Chrome\User Data");
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let user_data = home.join("chrome");

    let dir = user_data
        .join(profile)
        .join("Extensions")
        .join(ext_id)
        .join(version_dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("manifest.json"), manifest).unwrap();
}

/// Invoke `enumerate_browser_extensions` with `HOME` (plus the
/// matching Windows env vars) pointed at `tmp_home` so scanners only
/// see the synthetic layout. Env-var manipulation is process-wide and
/// would race other tests, so this runs inside an integration-test
/// binary where each `#[test]` executes in its own process? Actually,
/// Rust integration tests share a process too — so we serialize the
/// env mutation with a mutex.
fn with_fake_home<F, R>(tmp_home: &Path, f: F) -> R
where
    F: FnOnce() -> R,
{
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Snapshot prior env so we can restore it.
    let prior_home = std::env::var_os("HOME");
    let prior_user_profile = std::env::var_os("USERPROFILE");
    let prior_local = std::env::var_os("LOCALAPPDATA");
    let prior_appdata = std::env::var_os("APPDATA");

    // SAFETY: `set_var` / `remove_var` are not thread-safe on all
    // platforms, but this test serializes access via `LOCK` and runs
    // in its own integration-test binary.
    unsafe {
        std::env::set_var("HOME", tmp_home);
        std::env::set_var("USERPROFILE", tmp_home);
        std::env::set_var("LOCALAPPDATA", tmp_home.join("AppData/Local"));
        std::env::set_var("APPDATA", tmp_home.join("AppData/Roaming"));
    }

    let result = f();

    unsafe {
        match prior_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prior_user_profile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }
        match prior_local {
            Some(v) => std::env::set_var("LOCALAPPDATA", v),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
        match prior_appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
    }

    result
}

#[test]
fn enumerate_finds_synthetic_chrome_extension() {
    let tmp = TempDir::new("chrome");
    let home = tmp.path();

    let ext_id = "cjpalhdlnbpafiamejdnhcphjbkeiagm"; // 32-char Chrome-style id
    let manifest = r#"{
        "manifest_version": 3,
        "name": "uBlock Origin",
        "version": "1.52.0",
        "description": "Finally, an efficient blocker."
    }"#;
    write_chrome_extension(home, "Default", ext_id, "1.52.0_0", manifest);

    let exts: Vec<BrowserExtension> = with_fake_home(home, enumerate_browser_extensions);

    let ublock = exts
        .iter()
        .find(|e| e.browser == "chrome" && e.extension_id == ext_id)
        .unwrap_or_else(|| {
            panic!(
                "enumerate_browser_extensions should have found the synthetic Chrome extension; got: {:?}",
                exts
            )
        });
    assert_eq!(ublock.name, "uBlock Origin");
    assert_eq!(ublock.version, "1.52.0");
    assert_eq!(ublock.profile, "Default");
    assert_eq!(
        ublock.description.as_deref(),
        Some("Finally, an efficient blocker.")
    );
    assert!(ublock.path.contains("1.52.0_0"));
}

#[test]
fn scan_firefox_against_synthetic_profile() {
    let tmp = TempDir::new("ff-profile");
    let profile = tmp.path().join("abcd1234.default-release");
    fs::create_dir_all(&profile).unwrap();
    let extensions_json = r#"{
        "schemaVersion": 35,
        "addons": [
            {
                "id": "noscript@noscript.net",
                "version": "13.0.8",
                "type": "extension",
                "active": true,
                "userDisabled": false,
                "appDisabled": false,
                "path": "/tmp/noscript",
                "defaultLocale": {
                    "name": "NoScript",
                    "description": "Script blocker"
                }
            }
        ]
    }"#;
    fs::write(profile.join("extensions.json"), extensions_json).unwrap();

    let exts = scan_firefox(&profile);
    assert_eq!(exts.len(), 1);
    let ext = &exts[0];
    assert_eq!(ext.browser, "firefox");
    assert_eq!(ext.extension_id, "noscript@noscript.net");
    assert_eq!(ext.name, "NoScript");
    assert_eq!(ext.version, "13.0.8");
    assert_eq!(ext.enabled, Some(true));
    assert_eq!(ext.profile, "abcd1234.default-release");
}

#[test]
fn enumerate_on_empty_home_returns_empty_or_only_real_user_extensions() {
    // Pointing HOME at an empty directory must NOT crash and must NOT
    // report anything from the synthetic root (the real user may have
    // browsers installed; we just require none come from `tmp`).
    let tmp = TempDir::new("empty");
    let home = tmp.path();
    let exts = with_fake_home(home, enumerate_browser_extensions);
    let tmp_path = home.to_string_lossy().into_owned();
    for e in &exts {
        assert!(
            !e.path.starts_with(&*tmp_path),
            "empty synthetic home leaked path into results: {:?}",
            e
        );
    }
}
