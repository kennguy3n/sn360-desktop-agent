# Contributing to SN360 Desktop Agent

Thanks for your interest in contributing. This document covers the
things contributors need to know that are not obvious from
[`README.md`](./README.md) or the per-module docs under
[`docs/`](./docs/).

SN360 Desktop Agent is a proprietary product (see
[`LICENSE`](./LICENSE) and [`docs/licensing.md`](./docs/licensing.md)).
External contributions are accepted under the same proprietary
terms; by submitting a pull request you confirm you have the right
to license your contribution under those terms.

## Branching and commits

- Cut feature branches off `main`. The default name format is
  `devin/{timestamp}-{descriptive-slug}` (e.g.
  `devin/1779000000-fim-rate-limit`); other branch names are fine
  as long as they're descriptive and lowercase-with-hyphens.
- Keep commits focused. Prefer several small commits that each
  build and test cleanly over one mega-commit.
- Use conventional-commit style for the subject line where it
  fits (`feat(fim): …`, `fix(comms): …`, `docs: …`). The body can
  be longer and reference the issue or PR.
- Do **not** force-push `main` or `develop`. You may
  `git push --force-with-lease` on your own feature branch.

## Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs/))
- **Linux:** `pkg-config`, `libssl-dev`, `libyara-dev` (or
  distro-equivalent)
- **macOS:** Xcode Command Line Tools, `brew install yara`
- **Windows:** Visual Studio Build Tools (MSVC), a prebuilt YARA
  for Windows
- **Cross-compilation (optional):**
  [`cross`](https://github.com/cross-rs/cross) (`cargo install cross`)

YARA is a **required** runtime dependency of the Local Detection
Engine. Build hosts must have YARA development headers available.

## Local development

```bash
git clone https://github.com/kennguy3n/sn360-desktop-agent.git
cd sn360-desktop-agent

# Debug build
make build

# Run against the bundled Linux test config
cargo run --bin sda-agent -- --config ./tests/sda-test-config.yaml

# Release build (size-optimised)
make release
```

The agent reads YAML configuration from `--config <path>`. Working
examples live in [`tests/`](./tests/) and are also referenced from
[`docs/configuration-reference.md`](./docs/configuration-reference.md).

## CI strategy: fast lane vs. heavy lane

The repository runs on a two-lane CI model. The default fast lane
keeps PR turnaround under ~10 minutes; the heavy lane runs the
full, slow-but-thorough suite on demand and on `main`.

### Fast lane

Runs automatically on every PR and on every push to `main`. All
fast-lane checks are required for merge.

| Job | What it does |
|---|---|
| `lint` | `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`. |
| `unit` | `cargo test --workspace --lib --bins`. |
| `pr-gate` | `make test-pr` — `lint` + `unit` combined. This is the gate every PR must clear. |
| Docs path filter | Docs-only changes (`docs/**`, `*.md`, `LICENSE`) skip CI entirely. |

Locally, run the same gate with:

```bash
make test-pr
```

### Heavy lane

Runs the slow, infra-heavy jobs that the fast lane skips. **Not
required for merge** — gated to keep PR latency low.

| Job | What it does |
|---|---|
| `test-integration` | Per-crate integration tests. |
| `test-e2e-all` | The full set of hermetic Device Control and EDR E2E suites (see [`README.md`](./README.md#testing) for the list). |
| `benchmark-ci` | Performance regression gate — fails if idle RSS > 15 MB, idle CPU > 0.1 %, binary > 7 MB, or FIM burst peak > 3 %. |
| `nightly-fuzz` | `cargo +nightly fuzz run` against the harnesses in [`fuzz/`](./fuzz/) for 5 minutes per target. |

Triggers:

1. **Push to `main` or `develop`.** Always — catches integration
   regressions within minutes of merge.
2. **PR label `ci:full`.** Add the `ci:full` label to any PR and
   the heavy lane re-runs against it. Re-running by removing and
   re-adding the label is supported.
3. **Manual dispatch.** Run via the Actions tab and toggle
   `run_full_suite` / `run_benchmark`.

### When to opt in to heavy CI

- Your PR touches `sda-comms`, the wire-format encoders, the
  Platform Abstraction Layer (`sda-pal`), or shared crates.
- You're refactoring something that crosses module boundaries.
- You're cherry-picking onto a release branch and want stricter
  pre-merge gates.

### When **not** to opt in

- Single-module bug fix or doc-only change.
- A change with high unit coverage and no cross-module impact —
  the fast lane is sufficient.

## Tests

The repository ships three kinds of automated tests:

- **Unit tests** — colocated with each crate, run via
  `cargo test`. Use these for trait contracts, configuration
  parsing, regex behaviour, and similar internal invariants.
- **Per-crate integration tests** — under
  `crates/<crate>/tests/`. Use these when a feature involves more
  than one module inside a single crate or needs a fixture.
- **Workspace E2E suites** — under `crates/sda-agent/tests/`,
  invoked by `make e2e-*` targets. Each suite stands up a
  hermetic version of the agent against `Mock*` PAL
  implementations and exercises the full pipeline end-to-end.
  Mocks live behind a `test-support` feature on each module
  crate.

See [`tests/README.md`](./tests/README.md) for harness details and
the full target list.

When adding a new module:

1. Pick a `Mock*` implementation in the PAL trait for hermetic CI
   coverage. Real OS APIs that require elevated privileges
   (`task_for_pid`, `VirtualQueryEx` + `SeDebugPrivilege`,
   `/proc/<pid>/mem` + `CAP_SYS_PTRACE`, eBPF, WDK drivers) must
   be mockable.
2. Add a unit-test layer in `crates/<crate>/src/`.
3. Add an integration test under `crates/<crate>/tests/`.
4. Add or extend a `make e2e-*` suite under
   `crates/sda-agent/tests/`.
5. Register `.PHONY` and a `test-e2e-all` chain entry in the
   [`Makefile`](./Makefile).

## Style

- Run `cargo fmt --all` before pushing. The fast lane enforces
  this with `--check`.
- Clippy is run with `-D warnings`. Fix the warning; don't
  `#[allow]` it without a comment explaining why.
- Match the surrounding code's commenting style. Default to **no
  comment**; rely on naming. If you do add a comment, describe
  what the code does in general, not what the diff changes.

## Code quality

- Prefer minimal, focused edits. Avoid large refactors unless
  explicitly requested.
- Verify library availability before importing — check
  `Cargo.toml` and neighbouring crates first.
- Place all imports at the top of the file. Do not import inside
  functions or impl blocks.
- Never commit credentials, signing keys, or other secrets. If
  you spot a credential in the diff, stop and rotate it.
- Generated code must be immediately runnable; add all necessary
  imports, dependencies, and endpoints.

## Adding a new crate

1. Create the crate under `crates/<name>/`. Keep the `sda-`
   prefix on every workspace crate.
2. Add the path to `[workspace].members` in the top-level
   [`Cargo.toml`](./Cargo.toml). If the crate has external
   dependencies that other workspace crates also use, add the
   version constraint to `[workspace.dependencies]` and reference
   it as `crate-name = { workspace = true }` from the new crate's
   manifest.
3. If the crate exposes a `Mock*` for hermetic CI, gate it on a
   `test-support` Cargo feature so release builds don't carry
   it.
4. Wire the crate into [`README.md`](./README.md#workspace-layout)
   and (if it has a runtime config) into
   [`docs/configuration-reference.md`](./docs/configuration-reference.md).

## License headers

Every `.rs` source file must start with:

```rust
// Copyright 2024-2026 SN360 Inc. All rights reserved.
```

CI will reject files that don't carry the header.

## Pull requests

- Push your branch to your fork (or directly to the repo if you
  have write access).
- Open a PR against `main`. Use a descriptive title; the
  description should explain *why* in addition to *what*.
- Link any related issues.
- Make sure the fast lane is green before requesting review. Add
  the `ci:full` label if you want the heavy lane to run.
- Address review comments by pushing new commits to the same
  branch — don't squash or amend until the reviewer asks for it.

## Reporting bugs and security issues

- **Functional bugs:** open an issue with reproduction steps, the
  agent version, the OS, and a redacted excerpt of the relevant
  log lines.
- **Security vulnerabilities:** do **not** open a public issue.
  Follow the disclosure process in [`SECURITY.md`](./SECURITY.md).

## Documentation

User-facing documentation lives under [`docs/`](./docs/) and is
treated as part of the product. When you change behaviour:

- Update the relevant per-feature doc
  ([`docs/edr.md`](./docs/edr.md),
  [`docs/device-control.md`](./docs/device-control.md),
  [`docs/desktop-mdm.md`](./docs/desktop-mdm.md), and so on).
- If you add a configuration key, update
  [`docs/configuration-reference.md`](./docs/configuration-reference.md).
- Add a Changelog entry under `[Unreleased]` in
  [`CHANGELOG.md`](./CHANGELOG.md).

Documentation-only changes skip CI and merge fast — keep them
focused and self-contained.
