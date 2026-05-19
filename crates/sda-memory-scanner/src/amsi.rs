//! Windows AMSI (Antimalware Scan Interface) provider.
//!
//! Wires AMSI into the memory-scanner pipeline so
//! PowerShell / VBScript / JavaScript content that the OS sends
//! through AMSI for inspection is also visible to the SDA Local
//! Detection Engine.
//!
//! ## Compilation gate
//!
//! This module is compiled **only** when both:
//! - target_os is `"windows"`, and
//! - the `amsi` Cargo feature is enabled (`--features amsi`)
//!
//! The feature is off by default because:
//! 1. AMSI is Windows-only (`amsi.dll`, `AmsiInitialize`).
//! 2. The agent must run as `NT AUTHORITY\SYSTEM` (or the calling
//!    process must hold the `SeDebugPrivilege`) for AMSI to surface
//!    cross-process content.
//! 3. On every other target, the surface area must be replaced by
//!    [`crate::amsi_mock::MockAmsiProvider`] (which is `#[cfg(test)]`
//!    only) so unit tests can exercise the same code path.
//!
//! ## Wire model
//!
//! [`AmsiProvider`] implements [`crate::MemoryMatcher`].
//! [`crate::MemoryMatcher::match_bytes`] is called once per
//! interesting memory region (after the self-pid filter, the
//! allow-list filter, and the [`crate::is_interesting_region`]
//! filter — see [`crate::scan_process`]).  Hits are folded into
//! [`crate::MemoryAlertKind::AmsiMatch`] events on the bus by the
//! same `emit_alert` path that handles YARA hits — there is no
//! parallel publish path, so the redaction and self-pid invariants
//! enforced for YARA also apply to AMSI.
//!
//! ## Safety
//!
//! All FFI calls are wrapped behind RAII handles.
//! [`AmsiProvider::new`] calls `AmsiInitialize` once and stores the
//! resulting `HAMSICONTEXT` for the lifetime of the provider.
//! [`AmsiProvider::drop`] calls `AmsiUninitialize` exactly once.
//! Each [`AmsiProvider::match_bytes`] invocation opens a fresh
//! `HAMSISESSION` via `AmsiOpenSession`, uses
//! `AmsiScanBuffer` to submit the bytes, and closes the session via
//! `AmsiCloseSession` before returning — guaranteed by an
//! intermediate `AmsiSessionGuard`. This matches the AMSI provider
//! lifecycle documented in
//! <https://learn.microsoft.com/en-us/windows/win32/api/amsi/>.
//!
//! AMSI uses `HRESULT` for its return codes; we map any failure to
//! an empty `Vec<MemoryMatch>` rather than panicking, because a
//! failed scan must not stall the memory-scanner loop.

#![cfg(all(feature = "amsi", target_os = "windows"))]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::sync::OnceLock;

use tracing::{debug, warn};

use crate::{MemoryAlertKind, MemoryMatch, MemoryMatcher};
use sda_pal::memory_scanner::MemoryRegion;

// ---------------------------------------------------------------------------
// Raw FFI to amsi.dll
// ---------------------------------------------------------------------------
//
// We bind directly to `amsi.dll` via `extern "system"` to avoid
// pulling in the full `windows` crate (~80 MB of bindings) when the
// agent only needs five symbols.  The signatures here mirror
// `amsi.h` exactly; any drift will surface at link time on Windows.

type HRESULT = i32;
type HAMSICONTEXT = *mut c_void;
type HAMSISESSION = *mut c_void;

// AMSI_RESULT thresholds (from amsi.h).  Anything ≥ DETECTED is a
// hit by AMSI's own rules.
const AMSI_RESULT_DETECTED: i32 = 32768;

const S_OK: HRESULT = 0;

#[link(name = "amsi")]
extern "system" {
    fn AmsiInitialize(appName: *const u16, amsiContext: *mut HAMSICONTEXT) -> HRESULT;
    fn AmsiUninitialize(amsiContext: HAMSICONTEXT);
    fn AmsiOpenSession(amsiContext: HAMSICONTEXT, amsiSession: *mut HAMSISESSION) -> HRESULT;
    fn AmsiCloseSession(amsiContext: HAMSICONTEXT, amsiSession: HAMSISESSION);
    fn AmsiScanBuffer(
        amsiContext: HAMSICONTEXT,
        buffer: *const u8,
        length: u32,
        contentName: *const u16,
        amsiSession: HAMSISESSION,
        result: *mut i32,
    ) -> HRESULT;
}

// ---------------------------------------------------------------------------
// Public provider
// ---------------------------------------------------------------------------

/// AMSI provider.  Owns an `HAMSICONTEXT` for the lifetime of the
/// memory-scanner module.
pub struct AmsiProvider {
    context: HAMSICONTEXT,
}

// `HAMSICONTEXT` is opaque, and AMSI calls are thread-safe across
// the same context per the MSDN reference.  Tokio may move
// matchers across worker threads, so the manual marker is
// required.
unsafe impl Send for AmsiProvider {}
unsafe impl Sync for AmsiProvider {}

impl AmsiProvider {
    /// Initialise the AMSI context. Returns `None` if AMSI cannot
    /// be initialised (DLL missing, ACL denial, agent not running
    /// as SYSTEM, etc.) — callers MUST treat the absence of an
    /// `AmsiProvider` as "AMSI unavailable" and fall back to the
    /// YARA-only path. Never panics.
    pub fn new() -> Option<Self> {
        let app_name = utf16_with_nul("sn360-desktop-agent");
        let mut ctx: HAMSICONTEXT = std::ptr::null_mut();
        // SAFETY: `app_name` outlives the call; `ctx` is a valid
        // out-pointer.  AmsiInitialize either fills `ctx` or
        // returns a non-S_OK HRESULT.
        let hr = unsafe { AmsiInitialize(app_name.as_ptr(), &mut ctx as *mut _) };
        if hr != S_OK || ctx.is_null() {
            warn!(hresult = hr, "AmsiInitialize failed; AMSI disabled");
            return None;
        }
        debug!("AMSI context initialised");
        Some(Self { context: ctx })
    }
}

impl Drop for AmsiProvider {
    fn drop(&mut self) {
        if !self.context.is_null() {
            // SAFETY: `self.context` was returned by a successful
            // `AmsiInitialize`. AmsiUninitialize is safe to call
            // exactly once per context.
            unsafe { AmsiUninitialize(self.context) };
        }
    }
}

impl MemoryMatcher for AmsiProvider {
    fn match_bytes(&self, pid: u32, region: &MemoryRegion, bytes: &[u8]) -> Vec<MemoryMatch> {
        // Open a fresh AMSI session for every region scan; the
        // session bounds AMSI's stateful heuristics so a hit in
        // one region cannot poison the next region's verdict.
        let mut session: HAMSISESSION = std::ptr::null_mut();
        // SAFETY: `self.context` is non-null (checked at
        // construction); `session` is a valid out-pointer.
        let hr = unsafe { AmsiOpenSession(self.context, &mut session as *mut _) };
        if hr != S_OK || session.is_null() {
            warn!(
                pid,
                base = region.base,
                size = region.size,
                hresult = hr,
                "AmsiOpenSession failed; skipping region"
            );
            return Vec::new();
        }
        let _guard = AmsiSessionGuard {
            context: self.context,
            session,
        };

        let content_name = content_name_for(pid, region);
        let mut result: i32 = 0;
        // SAFETY: `bytes` is owned by the caller and outlives the
        // call; `content_name` is a NUL-terminated UTF-16 string
        // owned for the duration; `session` is valid until
        // `_guard` is dropped at end of scope.
        let hr = unsafe {
            AmsiScanBuffer(
                self.context,
                bytes.as_ptr(),
                bytes.len() as u32,
                content_name.as_ptr(),
                session,
                &mut result as *mut _,
            )
        };
        if hr != S_OK {
            warn!(pid, hresult = hr, "AmsiScanBuffer failed; skipping region");
            return Vec::new();
        }

        if result >= AMSI_RESULT_DETECTED {
            vec![MemoryMatch {
                alert_type: MemoryAlertKind::AmsiMatch,
                description: format!("AMSI detected malicious content (result={result})"),
            }]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// RAII guard that closes an AMSI session on drop. Lifted out into
/// a struct (rather than a `defer!`-style closure) so panic
/// unwinding still releases the session.
struct AmsiSessionGuard {
    context: HAMSICONTEXT,
    session: HAMSISESSION,
}

impl Drop for AmsiSessionGuard {
    fn drop(&mut self) {
        if !self.context.is_null() && !self.session.is_null() {
            // SAFETY: paired with the AmsiOpenSession call that
            // produced this `session` on the same `context`.
            unsafe { AmsiCloseSession(self.context, self.session) };
        }
    }
}

/// Render `<pid>@<region.base:#x>` as a UTF-16 NUL-terminated
/// content name. AMSI uses this for telemetry / event-log
/// correlation; it has no semantic effect on the scan verdict.
fn content_name_for(pid: u32, region: &MemoryRegion) -> Vec<u16> {
    static EMPTY: OnceLock<Vec<u16>> = OnceLock::new();
    if pid == 0 {
        return EMPTY.get_or_init(|| utf16_with_nul("")).clone();
    }
    utf16_with_nul(&format!("pid={pid}@base={:#x}", region.base))
}

fn utf16_with_nul(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! AMSI unit tests run *only* on Windows (the surrounding
    //! `#![cfg(all(...))]` already gates the module).  On any other
    //! target the tests in `crate::amsi_mock::tests` cover the same
    //! contract via `MockAmsiProvider`.

    use super::*;

    #[test]
    fn content_name_round_trips_utf16_nul() {
        let v = content_name_for(
            1234,
            &MemoryRegion {
                base: 0x7fff_1000,
                size: 4096,
                permissions: Default::default(),
                mapping: sda_pal::memory_scanner::MappingKind::Anonymous,
            },
        );
        // Must be NUL-terminated and decode back to the same
        // ASCII string.
        assert_eq!(v.last().copied(), Some(0u16));
        let decoded = String::from_utf16(&v[..v.len() - 1]).unwrap();
        assert_eq!(decoded, "pid=1234@base=0x7fff1000");
    }
}
