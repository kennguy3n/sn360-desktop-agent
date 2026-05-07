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
        e2e-device-control benchmark-ci deb rpm pkg msi

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --all

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
