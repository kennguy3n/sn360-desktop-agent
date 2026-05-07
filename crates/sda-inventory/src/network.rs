//! Network interface collection for the inventory module.
//!
//! - Linux: reads `/sys/class/net/` for MAC, state, MTU; `getifaddrs` for addresses.
//! - macOS: `getifaddrs` for addresses; `ifconfig` fallback for MAC addresses.
//! - Windows: enumerates adapters via `GetAdaptersAddresses` (IP Helper API).

use serde_json::Value;

/// Collect network interface information.
///
/// Returns a vector of syscollector payloads: one `dbsync_netiface` per
/// interface plus one `dbsync_netaddr` per address.
#[cfg(unix)]
pub fn collect_network_info() -> Vec<Value> {
    unix_impl::collect_network_info()
}

#[cfg(target_os = "windows")]
pub fn collect_network_info() -> Vec<Value> {
    windows_impl::collect_network_info()
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn collect_network_info() -> Vec<Value> {
    tracing::warn!("network interface collection is not yet supported on this platform");
    Vec::new()
}

#[cfg(unix)]
mod unix_impl {
    use std::net::IpAddr;

    use serde_json::Value;
    use tracing::{debug, warn};

    use crate::syscollector_format::{build_netaddr, build_netiface};

    pub fn collect_network_info() -> Vec<Value> {
        let mut payloads = Vec::new();

        match nix::ifaddrs::getifaddrs() {
            Ok(ifaddrs) => {
                let entries: Vec<_> = ifaddrs.collect();
                let mut seen_ifaces: std::collections::HashSet<String> =
                    std::collections::HashSet::new();

                for ifaddr in &entries {
                    let name = ifaddr.interface_name.clone();

                    // Emit one netiface entry per unique interface name.
                    if seen_ifaces.insert(name.clone()) {
                        let mac = read_mac_address(&name).unwrap_or_default();
                        let state =
                            read_interface_state(&name).unwrap_or_else(|| "unknown".to_string());
                        let mtu = read_interface_mtu(&name).unwrap_or(0);

                        let iface_data = serde_json::json!({
                            "name": name,
                            "mac": mac,
                            "state": state,
                            "mtu": mtu,
                        });
                        payloads.push(build_netiface(iface_data));
                        debug!(interface = %name, mac = %mac, state = %state, "collected network interface");
                    }

                    // Emit netaddr entries for each address.
                    if let Some(addr) = ifaddr.address {
                        if let Some(sock_addr) = addr.as_sockaddr_in() {
                            let ip = IpAddr::V4(sock_addr.ip());
                            let netmask = ifaddr
                                .netmask
                                .and_then(|n| {
                                    n.as_sockaddr_in().map(|s| IpAddr::V4(s.ip()).to_string())
                                })
                                .unwrap_or_default();
                            let broadcast = ifaddr
                                .broadcast
                                .and_then(|b| {
                                    b.as_sockaddr_in().map(|s| IpAddr::V4(s.ip()).to_string())
                                })
                                .unwrap_or_default();

                            let addr_data = serde_json::json!({
                                "iface": name,
                                "proto": 0,
                                "address": ip.to_string(),
                                "netmask": netmask,
                                "broadcast": broadcast,
                            });
                            payloads.push(build_netaddr(addr_data));
                        } else if let Some(sock_addr) = addr.as_sockaddr_in6() {
                            let ip = IpAddr::V6(sock_addr.ip());
                            let netmask = ifaddr
                                .netmask
                                .and_then(|n| {
                                    n.as_sockaddr_in6().map(|s| IpAddr::V6(s.ip()).to_string())
                                })
                                .unwrap_or_default();

                            let addr_data = serde_json::json!({
                                "iface": name,
                                "proto": 1,
                                "address": ip.to_string(),
                                "netmask": netmask,
                                "broadcast": "",
                            });
                            payloads.push(build_netaddr(addr_data));
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to enumerate network interfaces via getifaddrs");
            }
        }

        payloads
    }

    /// Read MAC address for a network interface.
    ///
    /// Linux: reads `/sys/class/net/{iface}/address`.
    /// macOS: parses `ifconfig` output as a fallback since `/sys/class/net/`
    /// does not exist on macOS.
    fn read_mac_address(iface: &str) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/sys/class/net/{}/address", iface);
            std::fs::read_to_string(path)
                .ok()
                .map(|s| s.trim().to_string())
        }
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("ifconfig")
                .arg(iface)
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("ether ") {
                    return Some(rest.trim().to_string());
                }
            }
            None
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = iface;
            None
        }
    }

    /// Read interface operational state.
    ///
    /// Linux: `/sys/class/net/{iface}/operstate`.
    /// macOS: parses `ifconfig` flags.
    fn read_interface_state(iface: &str) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/sys/class/net/{}/operstate", iface);
            std::fs::read_to_string(path)
                .ok()
                .map(|s| s.trim().to_string())
        }
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("ifconfig")
                .arg(iface)
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains("status: active") {
                Some("up".to_string())
            } else if text.contains("status: inactive") {
                Some("down".to_string())
            } else if text.contains("<UP") || text.contains(",UP") {
                Some("up".to_string())
            } else {
                Some("unknown".to_string())
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = iface;
            None
        }
    }

    /// Read interface MTU.
    ///
    /// Linux: `/sys/class/net/{iface}/mtu`.
    /// macOS: parses `ifconfig` output.
    fn read_interface_mtu(iface: &str) -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/sys/class/net/{}/mtu", iface);
            std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
        }
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("ifconfig")
                .arg(iface)
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let line = line.trim();
                // e.g. "mtu 1500"
                if let Some(rest) = line.strip_prefix("mtu ") {
                    return rest.split_whitespace().next().and_then(|v| v.parse().ok());
                }
                // or inside flags line: "flags=... mtu 1500"
                if let Some(idx) = line.find("mtu ") {
                    let after = &line[idx + 4..];
                    return after.split_whitespace().next().and_then(|v| v.parse().ok());
                }
            }
            None
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = iface;
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Loopback interface name varies by platform.
        #[cfg(target_os = "linux")]
        const LOOPBACK: &str = "lo";
        #[cfg(target_os = "macos")]
        const LOOPBACK: &str = "lo0";

        #[test]
        fn test_collect_network_info_returns_results() {
            let payloads = collect_network_info();
            // Should find at least the loopback interface.
            assert!(
                !payloads.is_empty(),
                "expected at least one network payload"
            );

            let has_netiface = payloads.iter().any(|p| p["type"] == "dbsync_netiface");
            assert!(has_netiface, "expected at least one netiface entry");
        }

        #[test]
        fn test_read_mac_address_loopback() {
            let mac = read_mac_address(LOOPBACK);
            // Linux loopback has a MAC (00:00:00:00:00:00); macOS lo0 does not.
            #[cfg(target_os = "linux")]
            assert!(mac.is_some(), "expected loopback MAC address on Linux");
            #[cfg(target_os = "macos")]
            assert!(mac.is_none(), "macOS loopback has no ether address");
        }

        #[test]
        fn test_read_interface_state_loopback() {
            let state = read_interface_state(LOOPBACK);
            assert!(state.is_some());
        }

        #[test]
        fn test_read_interface_mtu_loopback() {
            let mtu = read_interface_mtu(LOOPBACK);
            assert!(mtu.is_some());
            assert!(mtu.unwrap() > 0);
        }

        #[test]
        fn test_read_mac_address_nonexistent() {
            let mac = read_mac_address("nonexistent_iface_xyz");
            assert!(mac.is_none());
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_impl {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::slice;

    use serde_json::Value;
    use tracing::{debug, warn};

    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::{
        IfOperStatusDormant, IfOperStatusDown, IfOperStatusLowerLayerDown, IfOperStatusNotPresent,
        IfOperStatusTesting, IfOperStatusUnknown, IfOperStatusUp, IF_OPER_STATUS,
    };
    use windows::Win32::Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    use crate::syscollector_format::{build_netaddr, build_netiface};

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const NO_ERROR: u32 = 0;

    pub fn collect_network_info() -> Vec<Value> {
        let mut payloads = Vec::new();

        let buffer = match query_adapters() {
            Some(b) => b,
            None => return payloads,
        };

        // Safety: `buffer` outlives this loop and its contents form a
        // linked list of `IP_ADAPTER_ADDRESSES_LH` nodes laid out by
        // the kernel.
        let mut adapter: *const IP_ADAPTER_ADDRESSES_LH =
            buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !adapter.is_null() {
            let a = unsafe { &*adapter };

            // Prefer the user-visible FriendlyName, but fall back to
            // the AdapterName GUID when it is null/empty so we never
            // emit an empty `iface` in dbsync payloads.
            let friendly = unsafe { wide_ptr_to_string(a.FriendlyName.0) };
            let name = if friendly.is_empty() {
                unsafe { ansi_ptr_to_string(a.AdapterName.0) }
            } else {
                friendly
            };
            let mac = format_mac(&a.PhysicalAddress, a.PhysicalAddressLength as usize);
            let state = oper_status_str(a.OperStatus);
            let mtu = a.Mtu as u64;

            let iface_data = serde_json::json!({
                "name": name,
                "mac": mac,
                "state": state,
                "mtu": mtu,
            });
            payloads.push(build_netiface(iface_data));
            debug!(interface = %name, mac = %mac, state = %state, "collected network interface");

            let mut unicast: *const IP_ADAPTER_UNICAST_ADDRESS_LH = a.FirstUnicastAddress;
            while !unicast.is_null() {
                let u = unsafe { &*unicast };
                if let Some(entry) = render_unicast(&name, u) {
                    payloads.push(build_netaddr(entry));
                }
                unicast = u.Next;
            }

            adapter = a.Next;
        }

        payloads
    }

    /// Call `GetAdaptersAddresses` with the grow-on-overflow pattern
    /// recommended by MSDN. Returns `None` if the API fails.
    fn query_adapters() -> Option<Vec<u8>> {
        let flags = GAA_FLAG_INCLUDE_PREFIX
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;
        let family: u32 = AF_UNSPEC.0 as u32;

        let mut size: u32 = 15_000;
        let mut buffer: Vec<u8> = vec![0u8; size as usize];

        for _ in 0..3 {
            let result = unsafe {
                GetAdaptersAddresses(
                    family,
                    flags,
                    None,
                    Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                    &mut size,
                )
            };

            match result {
                NO_ERROR => return Some(buffer),
                ERROR_BUFFER_OVERFLOW => {
                    buffer.resize(size as usize, 0);
                }
                other => {
                    warn!(code = other, "GetAdaptersAddresses failed");
                    return None;
                }
            }
        }

        warn!("GetAdaptersAddresses kept overflowing; giving up");
        None
    }

    /// Convert a null-terminated wide string pointer into a Rust
    /// `String`. Returns an empty string if the pointer is null.
    ///
    /// # Safety
    /// `ptr` must be null or a valid pointer to a null-terminated
    /// UTF-16 sequence for the duration of this call.
    unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }

    /// Convert a null-terminated ANSI string pointer into a Rust
    /// `String`. Returns an empty string if the pointer is null.
    /// `AdapterName` is documented as ANSI and contains the adapter
    /// GUID (e.g. `{3F0A...}`), so plain ASCII handling is sufficient.
    ///
    /// # Safety
    /// `ptr` must be null or a valid pointer to a null-terminated
    /// byte sequence for the duration of this call.
    unsafe fn ansi_ptr_to_string(ptr: *const u8) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = slice::from_raw_parts(ptr, len);
        String::from_utf8_lossy(slice).into_owned()
    }

    fn format_mac(bytes: &[u8], len: usize) -> String {
        if len == 0 {
            return String::new();
        }
        let end = len.min(bytes.len());
        bytes[..end]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    fn oper_status_str(status: IF_OPER_STATUS) -> String {
        match status {
            s if s == IfOperStatusUp => "up".to_string(),
            s if s == IfOperStatusDown => "down".to_string(),
            s if s == IfOperStatusDormant => "dormant".to_string(),
            s if s == IfOperStatusNotPresent => "notpresent".to_string(),
            s if s == IfOperStatusLowerLayerDown => "lowerlayerdown".to_string(),
            s if s == IfOperStatusTesting => "testing".to_string(),
            s if s == IfOperStatusUnknown => "unknown".to_string(),
            _ => "unknown".to_string(),
        }
    }

    /// Build a `dbsync_netaddr` payload for a single unicast address.
    fn render_unicast(iface_name: &str, u: &IP_ADAPTER_UNICAST_ADDRESS_LH) -> Option<Value> {
        let sockaddr = u.Address.lpSockaddr;
        if sockaddr.is_null() {
            return None;
        }

        let family: ADDRESS_FAMILY = unsafe { (*sockaddr).sa_family };
        let prefix_len = u.OnLinkPrefixLength;

        if family == AF_INET {
            let sin = sockaddr as *const SOCKADDR_IN;
            let raw = unsafe { (*sin).sin_addr.S_un.S_addr };
            // `S_addr` is stored in network byte order.
            let ip = Ipv4Addr::from(u32::from_be(raw));
            let netmask = prefix_to_ipv4_netmask(prefix_len);
            Some(serde_json::json!({
                "iface": iface_name,
                "proto": 0,
                "address": ip.to_string(),
                "netmask": netmask,
                "broadcast": "",
            }))
        } else if family == AF_INET6 {
            let sin6 = sockaddr as *const SOCKADDR_IN6;
            let bytes = unsafe { (*sin6).sin6_addr.u.Byte };
            let ip = Ipv6Addr::from(bytes);
            let netmask = prefix_to_ipv6_netmask(prefix_len);
            Some(serde_json::json!({
                "iface": iface_name,
                "proto": 1,
                "address": ip.to_string(),
                "netmask": netmask,
                "broadcast": "",
            }))
        } else {
            None
        }
    }

    /// Convert a CIDR prefix length into a dotted IPv4 netmask string.
    fn prefix_to_ipv4_netmask(prefix: u8) -> String {
        if prefix == 0 {
            return "0.0.0.0".to_string();
        }
        let prefix = prefix.min(32);
        let mask: u32 = (!0u32) << (32 - prefix);
        Ipv4Addr::from(mask).to_string()
    }

    /// Convert an IPv6 on-link prefix length into an expanded IPv6
    /// netmask string (e.g. prefix `64` -> `ffff:ffff:ffff:ffff::`).
    ///
    /// The Unix path in this module emits the full expanded netmask
    /// for v6 addresses; matching that format keeps the Wazuh manager
    /// `dbsync_netaddr` consumer happy regardless of platform.
    fn prefix_to_ipv6_netmask(prefix: u8) -> String {
        let prefix = prefix.min(128) as u32;
        let mut bytes = [0u8; 16];
        let full_bytes = (prefix / 8) as usize;
        let remainder_bits = (prefix % 8) as u8;
        for b in bytes.iter_mut().take(full_bytes) {
            *b = 0xff;
        }
        if full_bytes < 16 && remainder_bits > 0 {
            bytes[full_bytes] = 0xffu8 << (8 - remainder_bits);
        }
        Ipv6Addr::from(bytes).to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn prefix_to_ipv4_netmask_common_values() {
            assert_eq!(prefix_to_ipv4_netmask(0), "0.0.0.0");
            assert_eq!(prefix_to_ipv4_netmask(8), "255.0.0.0");
            assert_eq!(prefix_to_ipv4_netmask(16), "255.255.0.0");
            assert_eq!(prefix_to_ipv4_netmask(24), "255.255.255.0");
            assert_eq!(prefix_to_ipv4_netmask(32), "255.255.255.255");
        }

        #[test]
        fn prefix_to_ipv6_netmask_common_values() {
            assert_eq!(prefix_to_ipv6_netmask(0), "::");
            assert_eq!(prefix_to_ipv6_netmask(64), "ffff:ffff:ffff:ffff::");
            assert_eq!(
                prefix_to_ipv6_netmask(128),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            );
            // Non-byte-aligned prefix.
            assert_eq!(prefix_to_ipv6_netmask(72), "ffff:ffff:ffff:ffff:ff00::");
        }

        #[test]
        fn prefix_to_ipv6_netmask_clamps_oversized_prefix() {
            assert_eq!(
                prefix_to_ipv6_netmask(255),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            );
        }

        #[test]
        fn format_mac_six_bytes() {
            let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0, 0];
            assert_eq!(format_mac(&bytes, 6), "de:ad:be:ef:00:11");
        }

        #[test]
        fn format_mac_zero_length_returns_empty() {
            let bytes = [0u8; 8];
            assert_eq!(format_mac(&bytes, 0), "");
        }

        #[test]
        fn collect_network_info_returns_results() {
            let payloads = collect_network_info();
            assert!(!payloads.is_empty(), "expected at least one adapter");
            assert!(payloads.iter().any(|p| p["type"] == "dbsync_netiface"));
        }
    }
}
