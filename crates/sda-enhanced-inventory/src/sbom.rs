//! CycloneDX SBOM (Software Bill of Materials) generator.
//!
//! Produces a CycloneDX 1.5 JSON document describing every piece of
//! software the enhanced-inventory module can see on the host:
//!
//! * installed OS packages — `dpkg-query` / `rpm` / Homebrew / WMI,
//!   reusing the collectors in [`crate`] internals rather than the
//!   heavier `sda-inventory` dependency chain,
//! * running processes — [`crate::running_software::enumerate_processes`],
//! * browser extensions —
//!   [`crate::browser_extensions::enumerate_browser_extensions`].
//!
//! The document is a single [`serde_json::Value`] so the enhanced-
//! inventory run loop can publish it through the existing event-bus
//! path (`EventKind::EnhancedInventoryUpdate` → `MessageType::Syscollector`)
//! without a separate codec.
//!
//! Hand-rolling the CycloneDX structure against the spec is preferred
//! over pulling in the `cyclonedx-bom` crate: the 1.5 shape we need is
//! small (bomFormat + specVersion + serialNumber + metadata +
//! components), and a dedicated dependency would measurably inflate
//! the binary-size budget committed to in the top-level README.
//!
//! Everything in this module is blocking — filesystem reads,
//! `dpkg-query`/`rpm`/`brew`/`wmic` subprocesses — and the run loop
//! always drives it through [`tokio::task::spawn_blocking`].

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::browser_extensions::{enumerate_browser_extensions, BrowserExtension};
use crate::running_software::{enumerate_processes, ProcessEntry};

/// Tool name reported in the CycloneDX `metadata.tools` block.
const TOOL_NAME: &str = "sda-enhanced-inventory";
/// Tool version, pulled from the crate manifest at compile time.
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
/// CycloneDX specification version emitted by this module.
pub const SPEC_VERSION: &str = "1.5";

/// One entry in the CycloneDX `components` array, before JSON
/// serialization.  Kept as an intermediate struct so the assembly
/// code can deduplicate components and then render each one with a
/// single `json!` template.
///
/// Exposed as `pub` so the hidden `build_sbom_from_parts` test helper
/// can accept a pre-built package list; the struct is not part of the
/// stable public API and may change without notice.
#[doc(hidden)]
pub struct Component {
    /// CycloneDX component type — `"application"` for processes and
    /// browser extensions, `"library"` for OS packages.
    kind: &'static str,
    /// Display name.
    name: String,
    /// Version string, if known.
    version: Option<String>,
    /// Human-readable description, if known.
    description: Option<String>,
    /// Package URL per the purl spec, if a well-defined scheme exists
    /// for this component's provenance.
    purl: Option<String>,
    /// `publisher` / vendor where known (OS packages, running
    /// processes on Windows).
    publisher: Option<String>,
    /// Free-form properties the manager can index without losing
    /// platform-specific context (Chromium profile name, Firefox
    /// extension id namespace, process pid, …).
    properties: Vec<(String, String)>,
}

impl Component {
    fn into_value(self) -> Value {
        let Component {
            kind,
            name,
            version,
            description,
            purl,
            publisher,
            properties,
        } = self;

        let mut obj = serde_json::Map::new();
        obj.insert("type".to_string(), Value::String(kind.to_string()));
        obj.insert("name".to_string(), Value::String(name));
        if let Some(v) = version {
            obj.insert("version".to_string(), Value::String(v));
        }
        if let Some(d) = description {
            obj.insert("description".to_string(), Value::String(d));
        }
        if let Some(p) = purl {
            obj.insert("purl".to_string(), Value::String(p));
        }
        if let Some(p) = publisher {
            obj.insert("publisher".to_string(), Value::String(p));
        }
        if !properties.is_empty() {
            let props: Vec<Value> = properties
                .into_iter()
                .map(|(name, value)| {
                    json!({
                        "name": name,
                        "value": value,
                    })
                })
                .collect();
            obj.insert("properties".to_string(), Value::Array(props));
        }
        Value::Object(obj)
    }
}

/// Generate a CycloneDX 1.5 SBOM describing the current host.
///
/// Blocking — call from [`tokio::task::spawn_blocking`]. Returns a
/// fully-populated [`serde_json::Value`] ready for serialization.
///
/// The function never fails: collectors that cannot run on the host
/// (no `dpkg-query`, no browser installed, non-Linux targets for a
/// Linux-only collector, …) contribute zero components, so callers
/// always receive a syntactically valid SBOM even on a completely
/// empty host.
pub fn generate_sbom() -> Value {
    let packages = collect_package_components();
    let processes = collect_process_components(&enumerate_processes());
    let extensions = collect_browser_extension_components(&enumerate_browser_extensions());
    build_bom(packages, processes, extensions, now_rfc3339(), new_serial())
}

/// Identical to [`generate_sbom`] but accepts caller-supplied input
/// slices. Used by the unit tests to assert on SBOM structure without
/// depending on the live host state.
#[doc(hidden)]
pub fn build_sbom_from_parts(
    packages: Vec<Component>,
    processes: &[ProcessEntry],
    extensions: &[BrowserExtension],
) -> Value {
    let processes = collect_process_components(processes);
    let ext_components = collect_browser_extension_components(extensions);
    build_bom(
        packages,
        processes,
        ext_components,
        now_rfc3339(),
        new_serial(),
    )
}

fn build_bom(
    packages: Vec<Component>,
    processes: Vec<Component>,
    extensions: Vec<Component>,
    timestamp: String,
    serial: String,
) -> Value {
    let mut components: Vec<Value> = Vec::with_capacity(
        packages
            .len()
            .saturating_add(processes.len())
            .saturating_add(extensions.len()),
    );
    for c in packages.into_iter().chain(processes).chain(extensions) {
        components.push(c.into_value());
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "sn360-desktop-agent",
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                }
            ],
        },
        "components": components,
    })
}

// ── Package collection ──────────────────────────────────────────────────────

/// Collect OS packages as CycloneDX components.
///
/// Tries the platform-appropriate package manager(s) synchronously so
/// the whole SBOM can be built inside a single `spawn_blocking` call:
/// `dpkg-query` → `rpm` on Linux, `brew list --versions` on macOS,
/// `wmic product get` on Windows. Any collector that is absent or
/// fails contributes zero components rather than aborting the SBOM.
fn collect_package_components() -> Vec<Component> {
    #[cfg(target_os = "linux")]
    {
        let dpkg = collect_dpkg();
        if !dpkg.is_empty() {
            dpkg
        } else {
            collect_rpm()
        }
    }
    #[cfg(target_os = "macos")]
    {
        collect_brew()
    }
    #[cfg(target_os = "windows")]
    {
        collect_wmic()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn collect_dpkg() -> Vec<Component> {
    let output = match std::process::Command::new("dpkg-query")
        .args([
            "-W",
            "-f",
            "${Package}\t${Version}\t${Architecture}\t${Maintainer}\n",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_dpkg(&stdout)
}

#[cfg(target_os = "linux")]
fn parse_dpkg(output: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let version = fields
            .get(1)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let architecture = fields
            .get(2)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let publisher = fields
            .get(3)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let purl = Some(build_purl_deb(
            &name,
            version.as_deref(),
            architecture.as_deref(),
        ));
        let mut properties = Vec::new();
        properties.push(("format".to_string(), "deb".to_string()));
        if let Some(arch) = &architecture {
            properties.push(("architecture".to_string(), arch.clone()));
        }
        out.push(Component {
            kind: "library",
            name,
            version,
            description: None,
            purl,
            publisher,
            properties,
        });
    }
    out
}

#[cfg(target_os = "linux")]
fn collect_rpm() -> Vec<Component> {
    let output = match std::process::Command::new("rpm")
        .args([
            "-qa",
            "--queryformat",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_rpm(&stdout)
}

#[cfg(target_os = "linux")]
fn parse_rpm(output: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.splitn(4, '\t').collect();
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let version = fields
            .get(1)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let architecture = fields
            .get(2)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let publisher = fields
            .get(3)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let purl = Some(build_purl_rpm(
            &name,
            version.as_deref(),
            architecture.as_deref(),
        ));
        let mut properties = Vec::new();
        properties.push(("format".to_string(), "rpm".to_string()));
        if let Some(arch) = &architecture {
            properties.push(("architecture".to_string(), arch.clone()));
        }
        out.push(Component {
            kind: "library",
            name,
            version,
            description: None,
            purl,
            publisher,
            properties,
        });
    }
    out
}

#[cfg(target_os = "macos")]
fn collect_brew() -> Vec<Component> {
    let output = match std::process::Command::new("brew")
        .args(["list", "--versions"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_brew(&stdout)
}

#[cfg(target_os = "macos")]
fn parse_brew(output: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        // Brew lists all installed versions; the last token is the
        // most recently installed one.
        let version = parts.last().map(|s| s.to_string());
        let purl = Some(build_purl_brew(name, version.as_deref()));
        out.push(Component {
            kind: "library",
            name: name.to_string(),
            version,
            description: None,
            purl,
            publisher: Some("homebrew".to_string()),
            properties: vec![("format".to_string(), "brew".to_string())],
        });
    }
    out
}

#[cfg(target_os = "windows")]
fn collect_wmic() -> Vec<Component> {
    let output = match std::process::Command::new("wmic")
        .args(["product", "get", "Name,Version", "/format:csv"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_wmic(&stdout)
}

#[cfg(target_os = "windows")]
fn parse_wmic(output: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut lines = output.lines();
    let _header = lines.next();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 3 {
            continue;
        }
        let name = fields[1].trim().to_string();
        if name.is_empty() {
            continue;
        }
        let version = {
            let v = fields[2].trim();
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        };
        let purl = Some(build_purl_generic("generic", &name, version.as_deref()));
        out.push(Component {
            kind: "library",
            name,
            version,
            description: None,
            purl,
            publisher: None,
            properties: vec![("format".to_string(), "msi".to_string())],
        });
    }
    out
}

// ── Running-process components ──────────────────────────────────────────────

fn collect_process_components(processes: &[ProcessEntry]) -> Vec<Component> {
    // Deduplicate by (name, path) — every running instance would
    // otherwise pollute the SBOM with dozens of entries for the same
    // binary (e.g. renderer processes). The SBOM is an "installed
    // software" view; pid counts live in the running-software
    // category instead.
    let mut by_key: BTreeMap<(String, Option<String>), (u32, Option<String>)> = BTreeMap::new();
    for p in processes {
        let key = (p.name.clone(), p.path.clone());
        let entry = by_key
            .entry(key)
            .or_insert_with(|| (0, p.publisher.clone()));
        entry.0 += 1;
        if entry.1.is_none() {
            entry.1 = p.publisher.clone();
        }
    }

    by_key
        .into_iter()
        .map(|((name, path), (count, publisher))| {
            let mut properties = Vec::new();
            properties.push(("category".to_string(), "running_software".to_string()));
            if let Some(path) = &path {
                properties.push(("path".to_string(), path.clone()));
            }
            properties.push(("instances".to_string(), count.to_string()));
            Component {
                kind: "application",
                name,
                version: None,
                description: None,
                purl: None,
                publisher,
                properties,
            }
        })
        .collect()
}

// ── Browser-extension components ────────────────────────────────────────────

fn collect_browser_extension_components(exts: &[BrowserExtension]) -> Vec<Component> {
    exts.iter()
        .map(|e| {
            let purl = browser_extension_purl(&e.browser, &e.extension_id, &e.version);
            let mut properties = Vec::new();
            properties.push(("category".to_string(), "browser_extension".to_string()));
            properties.push(("browser".to_string(), e.browser.clone()));
            if !e.profile.is_empty() {
                properties.push(("profile".to_string(), e.profile.clone()));
            }
            properties.push(("extension_id".to_string(), e.extension_id.clone()));
            if let Some(enabled) = e.enabled {
                properties.push(("enabled".to_string(), enabled.to_string()));
            }
            Component {
                kind: "application",
                name: e.name.clone(),
                version: if e.version.is_empty() {
                    None
                } else {
                    Some(e.version.clone())
                },
                description: e.description.clone(),
                purl,
                publisher: None,
                properties,
            }
        })
        .collect()
}

fn browser_extension_purl(browser: &str, id: &str, version: &str) -> Option<String> {
    if id.is_empty() {
        return None;
    }
    let (ty, namespace) = match browser {
        "chrome" => ("chrome-extension", None),
        "edge" => ("edge-extension", None),
        "firefox" => ("firefox-addon", None),
        "safari" => ("safari-extension", None),
        _ => return None,
    };
    Some(build_purl(
        ty,
        namespace,
        id,
        if version.is_empty() {
            None
        } else {
            Some(version)
        },
    ))
}

// ── purl builders ───────────────────────────────────────────────────────────

fn build_purl_deb(name: &str, version: Option<&str>, arch: Option<&str>) -> String {
    let base = build_purl("deb", Some("debian"), name, version);
    if let Some(a) = arch {
        format!("{base}?arch={}", purl_encode(a))
    } else {
        base
    }
}

fn build_purl_rpm(name: &str, version: Option<&str>, arch: Option<&str>) -> String {
    let base = build_purl("rpm", Some("fedora"), name, version);
    if let Some(a) = arch {
        format!("{base}?arch={}", purl_encode(a))
    } else {
        base
    }
}

#[cfg(target_os = "macos")]
fn build_purl_brew(name: &str, version: Option<&str>) -> String {
    build_purl("brew", None, name, version)
}

#[cfg(target_os = "windows")]
fn build_purl_generic(ty: &str, name: &str, version: Option<&str>) -> String {
    build_purl(ty, None, name, version)
}

fn build_purl(ty: &str, namespace: Option<&str>, name: &str, version: Option<&str>) -> String {
    let mut out = String::with_capacity(ty.len() + name.len() + 16);
    out.push_str("pkg:");
    out.push_str(ty);
    out.push('/');
    if let Some(ns) = namespace {
        out.push_str(&purl_encode(ns));
        out.push('/');
    }
    out.push_str(&purl_encode(name));
    if let Some(v) = version {
        out.push('@');
        out.push_str(&purl_encode(v));
    }
    out
}

/// Minimal percent-encoder for purl path segments.
///
/// The purl spec says the type, namespace, name, and version are
/// percent-encoded the same way URL path segments are. A full
/// implementation would pull in `percent-encoding`; here we escape
/// characters that actually collide with the purl grammar (`/`, `?`,
/// `#`, `@`, `%`, space) and percent-encode every non-ASCII byte so
/// multi-byte UTF-8 sequences round-trip correctly (e.g. a package
/// name `"café"` becomes `caf%C3%A9`, not mojibake). ASCII bytes that
/// aren't part of the purl grammar pass through unchanged.
fn purl_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'/' => out.push_str("%2F"),
            b'?' => out.push_str("%3F"),
            b'#' => out.push_str("%23"),
            b'@' => out.push_str("%40"),
            b'%' => out.push_str("%25"),
            b' ' => out.push_str("%20"),
            0x80..=0xFF => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0F) as usize] as char);
            }
            _ => out.push(b as char),
        }
    }
    out
}

// ── timestamps / serial numbers ─────────────────────────────────────────────

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Generate a CycloneDX `serialNumber` URN.
///
/// CycloneDX expects a URN of the form `urn:uuid:<uuid>`; we
/// synthesise a random-looking v4 UUID from the current nanos + a
/// process-local counter so the field is unique across back-to-back
/// SBOM runs without pulling in the full `uuid` crate.
fn new_serial() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    // Derive 16 pseudo-random bytes by mixing the three inputs. This
    // is not cryptographically random — CycloneDX only requires
    // uniqueness, not unpredictability.
    let mut bytes = [0u8; 16];
    let lo = nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(seq);
    let hi = pid
        .wrapping_mul(0xBF58_476D_1CE4_E5B9)
        .wrapping_add(nanos.rotate_left(17))
        ^ seq.rotate_left(29);
    bytes[..8].copy_from_slice(&lo.to_le_bytes());
    bytes[8..].copy_from_slice(&hi.to_le_bytes());
    // Stamp the UUID v4 variant/version bits so the value parses as
    // a well-formed RFC 4122 UUID.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_extensions::BrowserExtension;
    use crate::running_software::ProcessEntry;

    fn sample_process(pid: u32, name: &str, path: Option<&str>) -> ProcessEntry {
        ProcessEntry {
            pid,
            name: name.to_string(),
            path: path.map(|s| s.to_string()),
            started_at: None,
            publisher: None,
        }
    }

    fn sample_extension(browser: &str, id: &str, name: &str, version: &str) -> BrowserExtension {
        BrowserExtension {
            browser: browser.to_string(),
            profile: "Default".to_string(),
            extension_id: id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            description: Some("sample".to_string()),
            enabled: Some(true),
            path: "/tmp/ext".to_string(),
        }
    }

    fn sample_package(name: &str, version: &str, purl: &str) -> Component {
        Component {
            kind: "library",
            name: name.to_string(),
            version: Some(version.to_string()),
            description: None,
            purl: Some(purl.to_string()),
            publisher: Some("Ubuntu Developers".to_string()),
            properties: vec![("format".to_string(), "deb".to_string())],
        }
    }

    #[test]
    fn test_generate_sbom_returns_valid_cyclonedx_shape() {
        let bom = generate_sbom();
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], SPEC_VERSION);
        assert_eq!(bom["version"], 1);
        assert!(
            bom["serialNumber"]
                .as_str()
                .map(|s| s.starts_with("urn:uuid:"))
                .unwrap_or(false),
            "serialNumber must be a urn:uuid:<uuid> string, got: {:?}",
            bom["serialNumber"]
        );
        assert!(bom["metadata"]["timestamp"].is_string());
        assert!(bom["metadata"]["tools"].is_array());
        let tools = bom["metadata"]["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        assert_eq!(tools[0]["name"], TOOL_NAME);
        assert_eq!(tools[0]["version"], TOOL_VERSION);
        assert!(bom["components"].is_array());
    }

    #[test]
    fn test_metadata_timestamp_is_rfc3339() {
        let bom = generate_sbom();
        let ts = bom["metadata"]["timestamp"].as_str().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(ts).is_ok(),
            "timestamp is not RFC 3339: {ts:?}"
        );
    }

    #[test]
    fn test_build_sbom_from_parts_represents_every_category() {
        let packages = vec![sample_package("vim", "9.0", "pkg:deb/debian/vim@9.0")];
        let processes = vec![
            sample_process(1, "systemd", Some("/usr/lib/systemd/systemd")),
            sample_process(2, "systemd", Some("/usr/lib/systemd/systemd")), // duplicate, should collapse
            sample_process(3, "bash", Some("/usr/bin/bash")),
        ];
        let extensions = vec![sample_extension(
            "chrome",
            "cjpalhdlnbpafiamejdnhcphjbkeiagm",
            "uBlock Origin",
            "1.52.0",
        )];
        let bom = build_sbom_from_parts(packages, &processes, &extensions);
        let comps = bom["components"].as_array().unwrap();

        // 1 package + 2 distinct processes + 1 extension = 4 components.
        assert_eq!(comps.len(), 4, "components: {comps:?}");

        // Package component.
        let vim = comps
            .iter()
            .find(|c| c["name"] == "vim")
            .expect("vim package component");
        assert_eq!(vim["type"], "library");
        assert_eq!(vim["version"], "9.0");
        assert_eq!(vim["purl"], "pkg:deb/debian/vim@9.0");

        // Process components, with duplicate-pid collapse.
        let systemd = comps
            .iter()
            .find(|c| c["name"] == "systemd")
            .expect("systemd component");
        assert_eq!(systemd["type"], "application");
        let instances = systemd["properties"]
            .as_array()
            .and_then(|p| {
                p.iter()
                    .find(|kv| kv["name"] == "instances")
                    .and_then(|kv| kv["value"].as_str())
            })
            .unwrap();
        assert_eq!(instances, "2");

        // Browser-extension component.
        let ublock = comps
            .iter()
            .find(|c| c["name"] == "uBlock Origin")
            .expect("uBlock Origin component");
        assert_eq!(ublock["type"], "application");
        assert_eq!(ublock["version"], "1.52.0");
        assert_eq!(
            ublock["purl"],
            "pkg:chrome-extension/cjpalhdlnbpafiamejdnhcphjbkeiagm@1.52.0"
        );
    }

    #[test]
    fn test_empty_host_still_produces_valid_document() {
        let bom = build_sbom_from_parts(Vec::new(), &[], &[]);
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["specVersion"], SPEC_VERSION);
        assert_eq!(bom["components"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_browser_extension_purl_scheme_per_browser() {
        assert_eq!(
            browser_extension_purl("chrome", "abcd", "1.0"),
            Some("pkg:chrome-extension/abcd@1.0".to_string())
        );
        assert_eq!(
            browser_extension_purl("edge", "abcd", "1.0"),
            Some("pkg:edge-extension/abcd@1.0".to_string())
        );
        assert_eq!(
            browser_extension_purl("firefox", "noscript@noscript.net", "13.0.8"),
            Some("pkg:firefox-addon/noscript%40noscript.net@13.0.8".to_string())
        );
        assert_eq!(
            browser_extension_purl("safari", "com.example.ext", "1.0"),
            Some("pkg:safari-extension/com.example.ext@1.0".to_string())
        );
        assert_eq!(browser_extension_purl("lynx", "id", "1.0"), None);
        assert_eq!(browser_extension_purl("chrome", "", "1.0"), None);
    }

    #[test]
    fn test_build_purl_encodes_reserved_characters() {
        let purl = build_purl("deb", Some("deb ian"), "vim/x", Some("1@2"));
        assert_eq!(purl, "pkg:deb/deb%20ian/vim%2Fx@1%402");
    }

    #[test]
    fn test_purl_builders_attach_arch_qualifier() {
        let deb = build_purl_deb("bash", Some("5.2"), Some("amd64"));
        assert_eq!(deb, "pkg:deb/debian/bash@5.2?arch=amd64");
        let rpm = build_purl_rpm("bash", Some("5.2"), Some("x86_64"));
        assert_eq!(rpm, "pkg:rpm/fedora/bash@5.2?arch=x86_64");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_dpkg_builds_deb_purls() {
        let sample =
            "vim\t2:8.2.3995\tamd64\tUbuntu Developers\ncurl\t7.81.0\tamd64\tUbuntu Developers\n";
        let comps = parse_dpkg(sample);
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].name, "vim");
        assert_eq!(comps[0].version.as_deref(), Some("2:8.2.3995"));
        assert_eq!(
            comps[0].purl.as_deref(),
            Some("pkg:deb/debian/vim@2:8.2.3995?arch=amd64")
        );
        assert_eq!(comps[0].publisher.as_deref(), Some("Ubuntu Developers"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_dpkg_skips_empty_lines() {
        let sample = "\n\nvim\t9.0\tamd64\tUbuntu\n\n";
        let comps = parse_dpkg(sample);
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].name, "vim");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_rpm_builds_rpm_purls() {
        let sample = "bash\t5.2.15-3.fc39\tx86_64\tFedora Project\n";
        let comps = parse_rpm(sample);
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].name, "bash");
        assert_eq!(
            comps[0].purl.as_deref(),
            Some("pkg:rpm/fedora/bash@5.2.15-3.fc39?arch=x86_64")
        );
    }

    #[test]
    fn test_collect_process_components_deduplicates_by_name_and_path() {
        let processes = vec![
            sample_process(1, "bash", Some("/usr/bin/bash")),
            sample_process(2, "bash", Some("/usr/bin/bash")),
            sample_process(3, "bash", Some("/bin/bash")), // different path → distinct
            sample_process(4, "vim", None),
        ];
        let comps = collect_process_components(&processes);
        assert_eq!(comps.len(), 3);
    }

    #[test]
    fn test_collect_browser_extension_components_omits_purl_for_unknown_browser() {
        let exts = vec![BrowserExtension {
            browser: "lynx".to_string(),
            profile: "default".to_string(),
            extension_id: "abcd".to_string(),
            name: "x".to_string(),
            version: "1.0".to_string(),
            description: None,
            enabled: None,
            path: String::new(),
        }];
        let comps = collect_browser_extension_components(&exts);
        assert_eq!(comps.len(), 1);
        assert!(comps[0].purl.is_none());
    }

    #[test]
    fn test_generate_sbom_does_not_panic_on_host() {
        // Live host may have any combination of packages, processes,
        // and extensions; we only assert the call completes and
        // produces a syntactically valid envelope.
        let bom = generate_sbom();
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert!(bom["components"].is_array());
    }
}
