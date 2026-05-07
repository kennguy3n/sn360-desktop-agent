//! Persist seek positions so the agent resumes from where it left off after restart.

use std::collections::HashMap;
use std::path::PathBuf;

use tracing::{debug, warn};

/// Tracks seek offsets for monitored log files.
///
/// Persists `{path: offset}` mappings to a JSON file on disk.
pub struct SeekState {
    /// In-memory map of file path -> byte offset.
    offsets: HashMap<String, u64>,
    /// Path to the state file on disk.
    state_file: PathBuf,
}

impl SeekState {
    /// Load state from disk, or start fresh if the file doesn't exist.
    pub fn load(state_file: PathBuf) -> Self {
        let offsets = if state_file.exists() {
            match std::fs::read_to_string(&state_file) {
                Ok(contents) => serde_json::from_str::<HashMap<String, u64>>(&contents)
                    .unwrap_or_else(|e| {
                        warn!(error = %e, "corrupt seek state file, starting fresh");
                        HashMap::new()
                    }),
                Err(e) => {
                    warn!(error = %e, "failed to read seek state file, starting fresh");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        debug!(entries = offsets.len(), "loaded seek state");

        Self {
            offsets,
            state_file,
        }
    }

    /// Get the saved offset for a file, defaulting to 0.
    pub fn get_offset(&self, path: &str) -> u64 {
        self.offsets.get(path).copied().unwrap_or(0)
    }

    /// Update the offset for a file.
    pub fn set_offset(&mut self, path: &str, offset: u64) {
        self.offsets.insert(path.to_string(), offset);
    }

    /// Persist state to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.state_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(&self.offsets)?;
        std::fs::write(&self.state_file, json)?;
        debug!(path = %self.state_file.display(), "saved seek state");
        Ok(())
    }

    /// Return the default state file path.
    pub fn default_path() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/var/lib/sn360-desktop-agent/logcollector_state.json")
        }
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\ProgramData\SN360DesktopAgent\logcollector_state.json")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_load_empty_state() {
        let tmp = TempDir::new().unwrap();
        let state_file = tmp.path().join("state.json");
        let state = SeekState::load(state_file);
        assert_eq!(state.get_offset("/var/log/syslog"), 0);
    }

    #[test]
    fn test_set_and_get_offset() {
        let tmp = TempDir::new().unwrap();
        let state_file = tmp.path().join("state.json");
        let mut state = SeekState::load(state_file);

        state.set_offset("/var/log/syslog", 1024);
        assert_eq!(state.get_offset("/var/log/syslog"), 1024);
    }

    #[test]
    fn test_save_and_reload() {
        let tmp = TempDir::new().unwrap();
        let state_file = tmp.path().join("state.json");

        {
            let mut state = SeekState::load(state_file.clone());
            state.set_offset("/var/log/auth.log", 5000);
            state.set_offset("/var/log/syslog", 2000);
            state.save().unwrap();
        }

        let state = SeekState::load(state_file);
        assert_eq!(state.get_offset("/var/log/auth.log"), 5000);
        assert_eq!(state.get_offset("/var/log/syslog"), 2000);
    }

    #[test]
    fn test_corrupt_state_file() {
        let tmp = TempDir::new().unwrap();
        let state_file = tmp.path().join("state.json");
        std::fs::write(&state_file, "not valid json").unwrap();

        let state = SeekState::load(state_file);
        assert_eq!(state.get_offset("/any/path"), 0);
    }
}
