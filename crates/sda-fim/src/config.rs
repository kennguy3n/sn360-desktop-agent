//! FIM module configuration re-exports and defaults.

pub use sda_core::config::{FimConfig, FimDirectory};

/// Default database path for FIM state.
pub fn default_db_path() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/var/lib/sn360-desktop-agent/fim.db")
    }
    #[cfg(windows)]
    {
        std::path::PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\fim.db")
    }
}
