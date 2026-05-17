# Convenience targets for building the SN360 Desktop Agent.
#
# Usage:
#   make build            — Debug build for the host platform
#   make release          — Optimised release build for the host
#   make test             — Run all tests
#   make lint             — Format check + clippy
#   make all-targets      — Cross-compile for every supported target
#   make clean            — Remove build artefacts

CARGO  := cargo
CROSS  := cross

# All cross-compilation targets
TARGETS := \
	x86_64-unknown-linux-gnu \
	x86_64-unknown-linux-musl \
	aarch64-unknown-linux-gnu \
	x86_64-apple-darwin \
	aarch64-apple-darwin \
	x86_64-pc-windows-msvc

.PHONY: build release test lint fmt clippy all-targets clean e2e e2e-compat e2e-macos e2e-windows security-e2e \
        e2e-device-control e2e-software e2e-jit-admin e2e-app-control e2e-remote-support \
        e2e-device-policy e2e-mdm e2e-mdm-actions e2e-mdm-profile \
        e2e-process-telemetry e2e-lde-hotreload e2e-network-telemetry e2e-host-isolation \
        e2e-management-compat benchmark-ci deb rpm pkg msi \
        test-unit test-integration test-e2e-all test-full test-pr

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --all

# --- Test tiers ---------------------------------------------------------------

# Fast: unit tests only (lib tests in every crate). This is what PRs run.
test-unit:
	$(CARGO) test --all --lib

# Medium: unit + per-crate integration tests (no E2E).
# sda-agent's `tests/` directory holds the 6 hermetic Device Control
# E2E suites — those are owned by `test-e2e-all`, so we run sda-agent
# with `--bins` only (it has no library target; this exercises the
# inline unit tests in `src/main.rs`, `src/privilege.rs`, etc.) and
# let every other workspace crate run its full unit + integration
# suite.
test-integration:
	$(CARGO) test --workspace --exclude sda-agent
	$(CARGO) test --package sda-agent --bins

# All hermetic Device Control + Desktop MDM + EDR Parity E2E suites in one shot.
test-e2e-all:
	$(CARGO) test --package sda-agent --test e2e_device_control -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_software -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_jit_admin -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_app_control -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_remote_support -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_management_compat -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_device_policy -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_mdm -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_mdm_actions -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_mdm_profile -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_process_telemetry -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_lde_hotreload -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_network_telemetry -- --nocapture
	$(CARGO) test --package sda-agent --test e2e_host_isolation -- --nocapture

# Full: everything — unit + integration + all E2E + shell E2E + benchmarks.
test-full: test-integration test-e2e-all e2e e2e-compat security-e2e benchmark-ci

# PR gate: lint + unit tests only (fast).
test-pr: lint test-unit

lint: fmt clippy

fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

all-targets: $(addprefix build-,$(TARGETS))

build-%:
	$(CROSS) build --release --target $*

e2e:
	bash tests/scripts/run-e2e.sh

# Run the same 14-assertion E2E suite against an older Wazuh 4.x
# manager (4.7.x by default) to catch v4.x protocol drift.
e2e-compat:
	bash tests/scripts/run-compat-e2e.sh

# Performance regression gate used by CI. Exits non-zero if idle RSS,
# idle CPU, binary size, or FIM burst CPU exceed the thresholds in
# benchmark-results.md. Results land in target/benchmark-regression/.
benchmark-ci:
	bash tests/scripts/benchmark-regression.sh

e2e-macos:
	bash tests/scripts/run-e2e-macos.sh

e2e-windows:
	pwsh tests/scripts/run-e2e-windows.ps1

security-e2e:
	bash tests/scripts/run-security-e2e.sh

# Phase 1 Device Control E2E suite. Exercises every Phase 1 surface
# (admin inventory finding, posture snapshot, software-inventory
# bridge, agent vitals heartbeat, evidence record emission, idle-
# footprint gating) end-to-end. The suite lives in
# crates/sda-agent/tests/e2e_device_control.rs and is hermetic — no
# external server is required.
e2e-device-control:
	$(CARGO) test --package sda-agent --test e2e_device_control -- --nocapture

# Phase 2 Device Control E2E suite. Exercises every Phase 2 surface
# (catalogue manifest signature verification, maintenance windows,
# install/update/uninstall evidence chain, rollback orchestrator,
# approval-state recommendations, and the script runner) end-to-end.
# The suite lives in crates/sda-agent/tests/e2e_software.rs and is
# hermetic — no external server or package manager is required.
e2e-software:
	$(CARGO) test --package sda-agent --test e2e_software -- --nocapture

# Phase 3 JIT-admin E2E suite. Exercises every Phase 3 surface
# (request/approve/revoke chain, deny path, boot-sweep finalisation,
# drift detection, heartbeat-loss + power-profile revocations, and
# evidence-chain continuity across the lifecycle) end-to-end. The
# suite lives in crates/sda-agent/tests/e2e_jit_admin.rs and is
# hermetic — no external server or admin manager is required.
e2e-jit-admin:
	$(CARGO) test --package sda-agent --test e2e_jit_admin -- --nocapture

# Phase 4 app-control E2E suite (PHASES.md task 4.12). Exercises the
# WDAC + AppLocker (Windows) and dm-verity-aware (Linux) backends,
# the monitor / enforce controllers, dual-control rollback,
# anti-rollback + tampered-signature rejection, and evidence
# emission. The suite lives in
# crates/sda-agent/tests/e2e_app_control.rs and is hermetic — no
# OS-level capture stack is required.
e2e-app-control:
	$(CARGO) test --package sda-agent --test e2e_app_control -- --nocapture

# Phase 4 remote-support E2E suite (PHASES.md task 4.12). Walks the
# consent-gated session lifecycle end-to-end: explicit user click
# (approve/deny/timeout), wall-clock cap sweep, and the fail-closed
# stub prompt that prevents any production session from starting
# without a real consent UI. The suite lives in
# crates/sda-agent/tests/e2e_remote_support.rs and is hermetic — no
# capture or transport backend is required.
e2e-remote-support:
	$(CARGO) test --package sda-agent --test e2e_remote_support -- --nocapture

# Phase 5 management-compat E2E suite (PHASES.md task 5.7).
# Exercises the sda-management-compat shim translating
# Fleet-flavoured GitOps YAML into SDA-native config: valid
# Fleet -> SDA, EE-feature rejection, cross-tenant isolation, and
# round-trip into AgentConfig. Hermetic — no MSP control plane is
# required.
e2e-management-compat:
	$(CARGO) test --package sda-agent --test e2e_management_compat -- --nocapture

# Phase D2.6 USB / removable-media policy E2E suite. Hermetic — no
# real hardware. Walks block / allow / audit decisions, priority
# ordering, closed-by-default boot sentinel, last-known-good
# preservation across a tampered bundle, and a live UDS round-trip
# through the udev-helper IPC contract. Lives in
# crates/sda-agent/tests/e2e_device_policy.rs.
e2e-device-policy:
	$(CARGO) test --package sda-agent --test e2e_device_policy -- --nocapture

# Phase M1 Desktop MDM E2E suite (auto-remediation, recovery key
# escrow round-trip, OS patch scan + install, battery-aware
# deferral, 24h debounce). Hermetic — uses mock MdmProvider. Lives
# in crates/sda-agent/tests/e2e_mdm.rs.
e2e-mdm:
	$(CARGO) test --package sda-agent --test e2e_mdm -- --nocapture

# Phase M2 Desktop MDM action E2E suite (single-signature wipe is
# refused; two-signature wipe is accepted; remote lock; lost-mode
# enter/exit round-trip; AgentVitals.last_known_location after
# reconnect). Hermetic — uses mock MdmProvider. Lives in
# crates/sda-agent/tests/e2e_mdm_actions.rs.
e2e-mdm-actions:
	$(CARGO) test --package sda-agent --test e2e_mdm_actions -- --nocapture

# Phase M3 Desktop MDM declarative configuration profile E2E suite
# (push signed profile via bundle, verify password policy /
# screen-lock / Bluetooth enforcement; tampered profile rejected at
# signature check; MdmConfigProfileApplied event emitted with
# correct profile_id). Hermetic — uses mock MdmProvider. Lives in
# crates/sda-agent/tests/e2e_mdm_profile.rs.
e2e-mdm-profile:
	$(CARGO) test --package sda-agent --test e2e_mdm_profile -- --nocapture

# Phase E1.8 EDR process telemetry E2E suite. Exercises the
# ProcessMonitor PAL trait + sda-process-monitor module against a
# canned mock stream: parent-chain reconstruction, event dedup,
# overflow back-pressure, and behavioural ProcessChain rules (e.g.
# Word -> PowerShell). Hermetic — no netlink / ETW / Endpoint
# Security entitlement required. Lives in
# crates/sda-agent/tests/e2e_process_telemetry.rs.
e2e-process-telemetry:
	$(CARGO) test --package sda-agent --test e2e_process_telemetry -- --nocapture

# Phase E2.6 EDR LDE hot-reload E2E suite. Stands up a hand-rolled
# HTTP mock TRDS server, exercises signed-bundle pull, atomic
# pipeline swap, tampered-bundle rejection, unknown-key rejection,
# version substitution, and last-known-good preservation.
# Hermetic — no internet egress. Lives in
# crates/sda-agent/tests/e2e_lde_hotreload.rs.
e2e-lde-hotreload:
	$(CARGO) test --package sda-agent --test e2e_lde_hotreload -- --nocapture

# Phase E3.12 EDR network telemetry E2E suite. Exercises the
# NetworkMonitor + DnsMonitor PAL traits + sda-network-monitor
# module against canned mock streams: NetworkConnection / DnsQuery
# wire shape, dedup, UDP sampler bound, and LDE IP / domain IOC
# matching. Hermetic. Lives in
# crates/sda-agent/tests/e2e_network_telemetry.rs.
e2e-network-telemetry:
	$(CARGO) test --package sda-agent --test e2e_network_telemetry -- --nocapture

# Phase E3.12 EDR host isolation E2E suite. Exercises the
# HostIsolation PAL trait + sda-host-isolation module: signed
# IsolateHost / UnisolateHost SignedActionJob flow, control-plane
# CIDR + loopback safety invariants, idempotent dedup, validator
# rejection of unsigned jobs, disabled-config short-circuit.
# Hermetic — uses MockHostIsolation, no firewall touched. Lives in
# crates/sda-agent/tests/e2e_host_isolation.rs.
e2e-host-isolation:
	$(CARGO) test --package sda-agent --test e2e_host_isolation -- --nocapture

clean:
	$(CARGO) clean

# ---------------------------------------------------------------------------
# Packaging (P3.4). Each target compiles the release binary first, then
# hands it to the platform-specific build script under packaging/. Run
# the Windows target from a Windows host with WiX on PATH.
# ---------------------------------------------------------------------------
deb: release
	bash packaging/debian/build-deb.sh

rpm: release
	bash packaging/rpm/build-rpm.sh

pkg: release
	bash packaging/macos/build-pkg.sh

msi: release
	pwsh packaging/windows/build-msi.ps1
