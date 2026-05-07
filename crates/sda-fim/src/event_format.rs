//! Format FIM changes as Wazuh syscheck-compatible JSON.

use crate::db::FimEntry;

/// The type of change detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

impl ChangeType {
    #[allow(dead_code)]
    fn as_str(self) -> &'static str {
        match self {
            ChangeType::Added => "added",
            ChangeType::Modified => "modified",
            ChangeType::Deleted => "deleted",
        }
    }
}

/// Format a FIM change as a Wazuh syscheck-compatible JSON string.
///
/// Produces JSON matching the format consumed by Wazuh 4.x `analysisd`
/// (`fim_process_alert` in `syscheck.c`).  Key field names:
///   - `attributes`   – current (new) file metadata (or old for deletes)
///   - `old_attributes` – previous metadata (modified events only)
///   - `hash_sha256`  – SHA-256 field inside attributes
///
/// ```json
/// {"type":"event","data":{"path":"/etc/passwd","mode":"realtime",
///  "type":"modified","timestamp":1700000000,
///  "changed_attributes":["hash_sha256","size"],
///  "attributes":{...},"old_attributes":{...}}}
/// ```
pub fn format_syscheck_event(
    change_type: ChangeType,
    path: &str,
    old_entry: Option<&FimEntry>,
    new_entry: Option<&FimEntry>,
) -> String {
    let mut changed_attributes: Vec<&str> = Vec::new();

    // Determine which attributes changed.
    if let (Some(old), Some(new)) = (old_entry, new_entry) {
        if old.sha256 != new.sha256 {
            changed_attributes.push("hash_sha256");
        }
        if old.size != new.size {
            changed_attributes.push("size");
        }
        if old.permissions != new.permissions {
            changed_attributes.push("perm");
        }
        if old.uid != new.uid {
            changed_attributes.push("uid");
        }
        if old.gid != new.gid {
            changed_attributes.push("gid");
        }
        if old.mtime != new.mtime {
            changed_attributes.push("mtime");
        }
        if old.inode != new.inode {
            changed_attributes.push("inode");
        }
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let changed_json: Vec<String> = changed_attributes
        .iter()
        .map(|a| format!("\"{}\"", a))
        .collect();

    // Wazuh analysisd expects:
    //   - "attributes"     = current/new file metadata (or old for deletes)
    //   - "old_attributes" = previous metadata for modified events
    match change_type {
        ChangeType::Added => {
            let attrs = new_entry.map(format_attributes).unwrap_or_default();
            format!(
                "{{\"type\":\"event\",\"data\":{{\"path\":\"{}\",\"mode\":\"realtime\",\"type\":\"added\",\"timestamp\":{},\"attributes\":{{{}}}}}}}",
                escape_json_string(path),
                timestamp,
                attrs,
            )
        }
        ChangeType::Modified => {
            let attrs = new_entry.map(format_attributes).unwrap_or_default();
            let old_attrs = old_entry.map(format_attributes).unwrap_or_default();
            format!(
                "{{\"type\":\"event\",\"data\":{{\"path\":\"{}\",\"mode\":\"realtime\",\"type\":\"modified\",\"timestamp\":{},\"changed_attributes\":[{}],\"attributes\":{{{}}},\"old_attributes\":{{{}}}}}}}",
                escape_json_string(path),
                timestamp,
                changed_json.join(","),
                attrs,
                old_attrs,
            )
        }
        ChangeType::Deleted => {
            // For deletions, "attributes" carries the last-known file metadata.
            let attrs = old_entry.map(format_attributes).unwrap_or_default();
            format!(
                "{{\"type\":\"event\",\"data\":{{\"path\":\"{}\",\"mode\":\"realtime\",\"type\":\"deleted\",\"timestamp\":{},\"attributes\":{{{}}}}}}}",
                escape_json_string(path),
                timestamp,
                attrs,
            )
        }
    }
}

fn format_attributes(entry: &FimEntry) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Wazuh attribute field names (see syscheckd src/create_db.c).
    parts.push("\"type\":\"file\"".to_string());
    if let Some(ref h) = entry.sha256 {
        parts.push(format!("\"hash_sha256\":\"{}\"", h));
    }
    parts.push(format!("\"size\":{}", entry.size));
    parts.push(format!("\"perm\":\"{:o}\"", entry.permissions));
    parts.push(format!("\"uid\":\"{}\"", entry.uid));
    parts.push(format!("\"gid\":\"{}\"", entry.gid));
    parts.push(format!("\"mtime\":{}", entry.mtime));
    parts.push(format!("\"inode\":{}", entry.inode));

    parts.join(",")
}

/// Minimal JSON string escaping.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::FimEntry;

    fn sample_entry(sha: &str, size: i64) -> FimEntry {
        FimEntry {
            path: "/etc/passwd".to_string(),
            sha256: Some(sha.to_string()),
            size,
            permissions: 0o644,
            uid: 0,
            gid: 0,
            mtime: 1234567890,
            inode: 999,
            last_scan: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_format_modified_event() {
        let old = sample_entry("old_hash", 100);
        let new = sample_entry("new_hash", 200);

        let json =
            format_syscheck_event(ChangeType::Modified, "/etc/passwd", Some(&old), Some(&new));

        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "event");
        assert_eq!(parsed["data"]["path"], "/etc/passwd");
        assert_eq!(parsed["data"]["type"], "modified");
        assert_eq!(parsed["data"]["mode"], "realtime");
        assert!(parsed["data"]["timestamp"].as_u64().unwrap() > 0);

        let changed = parsed["data"]["changed_attributes"].as_array().unwrap();
        assert!(changed.contains(&serde_json::Value::String("hash_sha256".into())));
        assert!(changed.contains(&serde_json::Value::String("size".into())));

        // Wazuh uses "attributes" for current and "old_attributes" for previous.
        assert_eq!(parsed["data"]["old_attributes"]["hash_sha256"], "old_hash");
        assert_eq!(parsed["data"]["attributes"]["hash_sha256"], "new_hash");
        assert_eq!(parsed["data"]["attributes"]["size"], 200);
        assert_eq!(parsed["data"]["attributes"]["type"], "file");
    }

    #[test]
    fn test_format_added_event() {
        let new = sample_entry("abc123", 512);

        let json = format_syscheck_event(ChangeType::Added, "/etc/shadow", None, Some(&new));

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["data"]["type"], "added");
        assert_eq!(parsed["data"]["attributes"]["hash_sha256"], "abc123");
        assert_eq!(parsed["data"]["attributes"]["type"], "file");
        assert!(parsed["data"]["timestamp"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_format_deleted_event() {
        let old = sample_entry("abc123", 512);

        let json = format_syscheck_event(ChangeType::Deleted, "/etc/removed", Some(&old), None);

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["data"]["type"], "deleted");
        // For deletions, old file metadata goes into "attributes".
        assert_eq!(parsed["data"]["attributes"]["hash_sha256"], "abc123");
        assert_eq!(parsed["data"]["attributes"]["type"], "file");
    }

    #[test]
    fn test_format_with_special_chars_in_path() {
        let new = sample_entry("hash", 100);
        let json = format_syscheck_event(
            ChangeType::Added,
            "/tmp/file with \"quotes\"",
            None,
            Some(&new),
        );

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["data"]["path"], "/tmp/file with \"quotes\"");
    }

    #[test]
    fn test_permissions_format() {
        let entry = sample_entry("hash", 100);
        let json = format_syscheck_event(ChangeType::Added, "/etc/test", None, Some(&entry));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // 0o644 decimal = 420, formatted as octal "644"
        assert_eq!(parsed["data"]["attributes"]["perm"], "644");
    }
}
