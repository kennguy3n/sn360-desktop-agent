# SDA Release Process

This document describes how SN360 Desktop Agent (SDA) releases are
cut, signed, and published. It is the authoritative runbook for
maintainers driving `v*` tags.

## Overview

Releases are produced by the `Release` GitHub Actions workflow
(`.github/workflows/release.yml`), which fires when a maintainer
pushes a tag matching `v*`. The workflow:

1. Builds release binaries on `ubuntu-latest`, `macos-latest`, and
   `windows-latest` runners via `make release`.
2. Builds the native installers for each host: `.deb` / `.rpm`
   (Linux), `.pkg` (macOS), `.msi` (Windows).
3. Uploads each build's artefacts to the workflow run.
4. Collects every artefact on a Linux runner, computes per-file
   SHA-256 sums, and drafts a GitHub Release whose body is the
   `[Unreleased]` section of `CHANGELOG.md`.

The draft is **not** published automatically. A maintainer reviews
the artefacts, signs / notarises them out-of-band, and promotes the
draft once everything checks out.

## Versioning

SDA follows semantic versioning once it reaches `1.0`. Until then,
pre-1.0 tags may introduce breaking config or protocol changes at
each minor bump.

Pre-release tags use hyphenated suffixes:

- `v0.9.0-beta.1`, `v0.9.0-beta.2` — feature-frozen beta testing
- `v0.9.0-rc.1`                    — release candidate
- `v0.9.0`                         — stable

The workflow marks any tag containing `-` as a GitHub pre-release
automatically (`prerelease: true`).

## Cutting a release

1. **Finalise `CHANGELOG.md`.** Move the `[Unreleased]` section to
   a new section headed by the version and date, leave a fresh
   empty `[Unreleased]` placeholder on top, and push the change
   through a PR. The release workflow uses the `[Unreleased]`
   section as the release body, so do this **before** tagging if
   you want the notes scoped to this release only.

2. **Verify CI is green on `main`.** At minimum: the `check`,
   `test`, `audit`, and `build` jobs on
   `.github/workflows/ci.yml`.

3. **Re-run the benchmark regression gate locally.**

   ```
   sudo apt-get install -y sysstat bc
   make benchmark-ci
   ```

   This exits non-zero if idle RSS, idle CPU, binary size, or FIM
   burst peak exceed the budgets in `benchmark-results.md`. Do not
   tag unless this passes.

4. **Create and sign the tag.** Tags must be signed with a
   maintainer's GPG / SSH key.

   ```
   git tag -s v0.9.0-beta.1 -m "Beta 1 release"
   git push origin v0.9.0-beta.1
   ```

5. **Watch the release workflow.** The `build-release` jobs take
   ~10 minutes per runner; `draft-release` finalises the GitHub
   Release draft once all three complete. A failure in any matrix
   leg fails the whole run; do not retry by re-pushing the tag —
   delete the tag, fix the issue, and push a fresh tag with a
   bumped suffix.

6. **Download the artefacts.** From the workflow run or the draft
   release, grab:

   - `sda-agent` (Linux x86_64, unsigned)
   - `sda-agent.exe` (Windows x86_64, unsigned)
   - `sda-agent` (macOS universal, unsigned)
   - `*.deb`, `*.rpm`, `*.pkg`, `*.msi` installers (unsigned)
   - `SHA256SUMS`

7. **Sign / notarise out-of-band** (see below).

8. **Replace the unsigned artefacts on the draft release** with the
   signed ones. Update `SHA256SUMS` with the post-signing hashes
   and re-upload.

9. **Publish the draft release.** Once every artefact is signed and
   the release notes read well, click *Publish*.

10. **Announce.** Post the release URL in the appropriate channel
    and update the product-status channels.

## Signing policy

### Linux

- `.deb` packages are signed with the SN360 apt repository
  key via `dpkg-sig --sign builder file.deb`. The key is stored
  in the team 1Password vault under *SDA Linux apt signing*.
- `.rpm` packages are signed with `rpmsign --addsign file.rpm`
  using the matching yum repository key (same vault).
- The statically-linked ELF binary is not itself signed; operators
  verify it via the package signature.

### macOS

- The `sda-agent` binary and the `.pkg` installer must be signed
  with the SN360 Apple Developer ID Application / Installer
  certificates, then notarised via `notarytool submit --wait`.
- Gatekeeper-stapling (`xcrun stapler staple`) must succeed on the
  `.pkg` before publication — otherwise macOS 14+ will prompt for
  confirmation on first launch.
- Developer ID certificates live in the team 1Password vault under
  *SDA Apple Developer ID signing* and *SDA Apple Developer ID
  installer*.

### Windows

- The `sda-agent.exe` binary and the `.msi` installer must be
  signed with the SN360 EV code-signing certificate using
  `signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 ...`.
- The EV certificate is stored on a hardware token and must be
  signed from a maintainer workstation with the token attached.
- For SmartScreen reputation, submit signed binaries to Microsoft
  via the Windows Defender portal after every new version.

### Checksums

After replacing artefacts with their signed versions, regenerate
`SHA256SUMS`:

```
cd release-upload
shopt -s nullglob
rm -f SHA256SUMS
for f in *; do sha256sum "$f" >> SHA256SUMS; done
```

Upload the refreshed `SHA256SUMS` to the draft release before
publishing.

## Triggering the release workflow manually

If a scheduled workflow run needs to be re-triggered without
re-tagging (e.g. a flaky runner), use the *Re-run all jobs* button
on the failed run. The workflow has **no** `workflow_dispatch`
trigger by design — all releases are tag-driven so the tag
history is the single source of truth.

## Promoting a draft to a published release

Draft releases are only visible to repository maintainers. To
promote:

1. Verify every asset is signed and the `SHA256SUMS` is current.
2. Edit the release body if the `[Unreleased]` section needs
   polishing.
3. Toggle off *Set as a pre-release* only for stable `vX.Y.Z`
   tags.
4. Click *Publish release*.

Published releases are immutable from a consumer's perspective:
never delete or retag a published release. If something needs to
be pulled, tag `vX.Y.Z+1` with a `Reverts vX.Y.Z` note and publish
a replacement.

## Rollback

If a published release exposes a regression:

1. Decide whether to **yank** (mark the published release as
   pre-release and add a `[YANKED]` prefix to the title, linking to
   the successor version), or to **supersede** (publish
   `vX.Y.(Z+1)` and leave the flawed release in place with a
   `Superseded by …` note).
2. Yank the apt / yum repo signed artefacts by removing them from
   the repository index and rebuilding the repository metadata.
3. For auto-update clients, bump the manifest served by
   `sda_updater` to point at the superseding version. Clients pick
   this up within a manifest-poll interval (default 6 hours).

## Checklist (paste into release PR)

```
- [ ] CHANGELOG.md [Unreleased] moved to vX.Y.Z section
- [ ] `cargo audit --deny warnings` green
- [ ] `make benchmark-ci` under all thresholds
- [ ] `make e2e` 14/14 pass against Wazuh 4.9.2
- [ ] `make security-e2e` 10/10 pass
- [ ] Tag signed (`git tag -s vX.Y.Z`)
- [ ] Release workflow completed on all three OS legs
- [ ] Linux .deb/.rpm signed with repo key
- [ ] macOS .pkg signed + notarised + stapled
- [ ] Windows .msi and .exe signed with EV cert + submitted to SmartScreen
- [ ] SHA256SUMS regenerated after signing
- [ ] Release notes body reviewed
- [ ] Draft promoted to published release
- [ ] Announcement posted
```
