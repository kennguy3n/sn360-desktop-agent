//! Embedded default rule bundle (Phase E2.4).
//!
//! When the on-disk `rule_bundle_path` is missing or unreadable AND no
//! TRDS endpoint is configured, the LDE falls back to this small set
//! of baseline rules so the default-ON configuration (Phase E2.3) still
//! provides immediate value out-of-the-box.
//!
//! Keep this list intentionally minimal — operators are expected to
//! ship their own bundle via TRDS for production deployments.

use crate::rule_store::{
    BehavioralRule, BehavioralRuleKind, IocList, IpIoc, RuleBundle, StringIoc, SEV_HIGH, SEV_MEDIUM,
};

/// Bundle version reserved for the agent's embedded baseline.  Any
/// TRDS bundle worth installing will carry a higher version number.
pub const DEFAULT_BUNDLE_VERSION: u64 = 1;

/// Construct the baseline bundle.  This is cheap (a handful of `Vec`
/// allocations) so we rebuild on demand rather than memoising.
pub fn default_bundle() -> RuleBundle {
    RuleBundle {
        version: DEFAULT_BUNDLE_VERSION,
        generated_at: "2026-05-01T00:00:00Z".to_string(),
        iocs: IocList {
            strings: vec![
                // Public sinkhole used by RFC-2606 — a safe synthetic
                // IOC that lets the bundle smoke-test end-to-end without
                // shipping real threat intel.
                StringIoc {
                    id: "edr-default-domain-001".into(),
                    value: "evil.example.com".into(),
                    kind: "domain".into(),
                    severity: SEV_HIGH.into(),
                    description: "Default baseline domain IOC (synthetic)".into(),
                },
                StringIoc {
                    id: "edr-default-domain-002".into(),
                    value: "malware.invalid".into(),
                    kind: "domain".into(),
                    severity: SEV_HIGH.into(),
                    description: "Default baseline domain IOC (synthetic)".into(),
                },
            ],
            hashes: vec![],
            ips: vec![IpIoc {
                id: "edr-default-ip-001".into(),
                ip: "203.0.113.9".into(),
                severity: SEV_MEDIUM.into(),
                description: "TEST-NET-3 sample IOC (RFC 5737)".into(),
            }],
        },
        behavioral: vec![
            BehavioralRule {
                id: "edr-process-chain-001".into(),
                severity: SEV_HIGH.into(),
                description: "Office application spawned PowerShell / cmd".into(),
                event_source: "process".into(),
                kind: BehavioralRuleKind::ProcessChain {
                    name_regex: r"^(powershell|cmd)\.exe$".into(),
                    parent_chain_regex: r".*(winword|excel|outlook|powerpnt)\.exe.*".into(),
                },
            },
            BehavioralRule {
                id: "edr-process-chain-002".into(),
                severity: SEV_HIGH.into(),
                description: "wmiprvse.exe spawned rundll32.exe".into(),
                event_source: "process".into(),
                kind: BehavioralRuleKind::ProcessChain {
                    name_regex: r"^rundll32\.exe$".into(),
                    parent_chain_regex: r".*wmiprvse\.exe.*".into(),
                },
            },
            BehavioralRule {
                id: "edr-process-chain-003".into(),
                severity: SEV_HIGH.into(),
                description: "lsass.exe accessed by non-system process".into(),
                event_source: "process".into(),
                kind: BehavioralRuleKind::ProcessChain {
                    // Note: this fires on `lsass.exe` *creation* from an
                    // unexpected parent — full handle-open detection
                    // requires kernel telemetry (Phase E4).
                    name_regex: r"^lsass\.exe$".into(),
                    parent_chain_regex: r"^(?!.*\b(services|wininit|smss)\.exe).*$".into(),
                },
            },
        ],
        yara_paths: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bundle_has_baseline_rules() {
        let b = default_bundle();
        assert_eq!(b.version, DEFAULT_BUNDLE_VERSION);
        assert!(!b.iocs.strings.is_empty(), "expected baseline string IOCs");
        assert!(!b.iocs.ips.is_empty(), "expected baseline IP IOCs");
        assert!(
            b.behavioral.len() >= 3,
            "expected at least 3 baseline process-chain rules"
        );
    }

    #[test]
    fn default_bundle_round_trips_through_msgpack() {
        let b = default_bundle();
        let bytes = b.to_msgpack().unwrap();
        let decoded = RuleBundle::from_msgpack(&bytes).unwrap();
        assert_eq!(decoded.version, b.version);
        assert_eq!(decoded.behavioral.len(), b.behavioral.len());
    }
}
