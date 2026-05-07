//! Wazuh syscollector wire format helpers.
//!
//! Each inventory message is formatted as `syscollector:{json_payload}`
//! (the `d:` routing prefix is added by `encode_body()` in the protocol layer).

use serde_json::Value;

/// Wrap a JSON payload into the Wazuh syscollector wire format.
///
/// Returns a string like `syscollector:{"type":"dbsync_osinfo",...}`.
/// The `d:` routing prefix is added later by `encode_body()` in the protocol layer.
pub fn wrap_syscollector(json_payload: &Value) -> String {
    format!("syscollector:{}", json_payload)
}

/// Build a dbsync osinfo payload.
pub fn build_osinfo(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_osinfo",
        "operation": "MODIFIED",
        "data": data,
    })
}

/// Build a dbsync packages payload.
pub fn build_packages(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_packages",
        "operation": "MODIFIED",
        "data": data,
    })
}

/// Build a dbsync network interface payload.
pub fn build_netiface(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_netiface",
        "operation": "MODIFIED",
        "data": data,
    })
}

/// Build a dbsync network address payload.
pub fn build_netaddr(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_netaddr",
        "operation": "MODIFIED",
        "data": data,
    })
}

/// Build a dbsync hardware info payload.
pub fn build_hwinfo(data: Value) -> Value {
    serde_json::json!({
        "type": "dbsync_hwinfo",
        "operation": "MODIFIED",
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrap_syscollector_format() {
        let payload = serde_json::json!({"type": "dbsync_osinfo", "data": {}});
        let wire = wrap_syscollector(&payload);
        assert!(wire.starts_with("syscollector:"));
        assert!(wire.contains("dbsync_osinfo"));
    }

    #[test]
    fn test_build_osinfo() {
        let data = serde_json::json!({"os_name": "Ubuntu"});
        let result = build_osinfo(data);
        assert_eq!(result["type"], "dbsync_osinfo");
        assert_eq!(result["data"]["os_name"], "Ubuntu");
    }

    #[test]
    fn test_build_packages() {
        let data = serde_json::json!({"name": "vim", "version": "8.2"});
        let result = build_packages(data);
        assert_eq!(result["type"], "dbsync_packages");
        assert_eq!(result["data"]["name"], "vim");
    }

    #[test]
    fn test_build_netiface() {
        let data = serde_json::json!({"name": "eth0"});
        let result = build_netiface(data);
        assert_eq!(result["type"], "dbsync_netiface");
    }

    #[test]
    fn test_build_netaddr() {
        let data = serde_json::json!({"address": "192.168.1.1"});
        let result = build_netaddr(data);
        assert_eq!(result["type"], "dbsync_netaddr");
    }

    #[test]
    fn test_build_hwinfo() {
        let data = serde_json::json!({"cpu_name": "Intel"});
        let result = build_hwinfo(data);
        assert_eq!(result["type"], "dbsync_hwinfo");
    }
}
