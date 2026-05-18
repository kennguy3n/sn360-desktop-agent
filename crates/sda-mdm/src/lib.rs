//! `sda-mdm` — ShieldNet Desktop MDM module (Phases M1–M3).
//!
//! This crate is the agent-side implementation of the cross-platform
//! MDM surface specified in `docs/desktop-mdm.md` (with the cross-
//! surface architecture in `docs/architecture.md` § 4 and § 7).
//! It bundles seven sub-modules
//! that share one [`sda_pal::mdm::MdmProvider`] instance, an
//! [`sda_event_bus::EventBus`] for surfacing results, and the
//! [`sda_device_control::router`] pipeline for inbound
//! [`sda_device_control::signed_job::SignedActionJob`] dispatch:
//!
//! | Sub-module                  | Trigger                                            | Phase |
//! |-----------------------------|----------------------------------------------------|-------|
//! | [`auto_remediate`]          | Posture-snapshot subscriber + 24 h debounce        | M1.2  |
//! | [`recovery_key`]            | Once-per-boot after first comms handshake          | M1.3  |
//! | [`os_patch`]                | Maintenance-window tick + battery-aware deferral   | M1.4  |
//! | [`config_profile`]          | Filesystem watcher on TRDS bundle path             | M3    |
//! | [`wipe`]                    | `SignedActionJob` → `ActionKind::RemoteWipe`       | M2.1  |
//! | [`lock`]                    | `SignedActionJob` → `ActionKind::RemoteLock`       | M2.2  |
//! | [`lost_mode`]               | `SignedActionJob` → Enter/ExitLostMode             | M2.3  |
//!
//! Unlike Device Control (which defaults `enabled = false`), the MDM
//! module defaults to **ON** — operators that need to disable it
//! must explicitly set `modules.mdm.enabled = false`. See
//! [`sda_core::config::MdmConfig`].

pub mod auto_remediate;
pub mod config_profile;
pub mod lock;
pub mod lost_mode;
pub mod module;
pub mod os_patch;
pub mod recovery_key;
pub mod wipe;

pub use module::{MdmModule, MdmModuleError};
