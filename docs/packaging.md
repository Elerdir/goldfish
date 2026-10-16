# Packaging & release (Phase 13)

How Goldfish is bundled into installers, signed, and released. Bundling is driven
by Tauri's `bundle` config in [`crates/goldfish-tauri/tauri.conf.json`](../crates/goldfish-tauri/tauri.conf.json).

## Artifacts per platform

| Platform | Targets                | Output (relative to repo root)                         |
|----------|------------------------|--------------------------------------------------------|
| Windows  | `msi` (WiX), `nsis`    | `target/release/bundle/msi/*.msi`, `…/nsis/*-setup.exe` |
| macOS    | `dmg`, `app`           | `target/release/bundle/dmg/*.dmg`, `…/macos/*.app`     |
| Linux    | `deb`, `appimage`      | `target/release/bundle/deb/*.deb`, `…/appimage/*.AppImage` |

The MSI ships in English; the NSIS installer is multilingual (English / German /
Czech) with a language picker. Install mode is **per-user** (`currentUser`), so no
administrator elevation is required.

> **App identity:** the bundle identifier is `com.goldfish.desktop`. It determines
> the per-user data directory (where `vault.db` + `vault.meta.json` live) and the
> OS keychain service name — do **not** change it after the first public release.

## Prerequisites

Same as the dev toolchain (see the root `README.md`), plus the bundlers Tauri
downloads on first run:

- **Windows:** Rust + MSVC Build Tools 2022, Perl + NASM (for vendored OpenSSL),
  pnpm. WiX 3 and NSIS are fetched automatically by `cargo tauri build` (needs
  network on the first build).
- **macOS:** Xcode command-line tools; for a universal binary,
  `rustup target add aarch64-apple-darwin x86_64-apple-darwin`.
- **Linux:** `libwebkit2gtk-4.1-dev libgtk-3-dev libappindicator3-dev librsvg2-dev patchelf`.

## Building locally

```powershell
# Windows — produces MSI + NSIS
.\build-installer.bat
# …or directly:
cargo tauri build --bundles msi,nsis
```

```bash
# macOS — universal DMG
cargo tauri build --target universal-apple-darwin --bundles dmg

# Linux — deb + AppImage
cargo tauri build --bundles deb,appimage
```

The frontend is built automatically: Tauri runs `beforeBuildCommand` (`pnpm build`)
inside `src-frontend/` and bundles the emitted `dist/`.

## Versioning

The version lives in three places that must match (release builds verify tag == version):

- `Cargo.toml` → `[workspace.package] version`
- `crates/goldfish-tauri/tauri.conf.json` → `version`
- `src-frontend/package.json` → `version`

Never bump them by hand: Dispatch runs `scripts/bump-version.mjs` in a commit reachable
only from the release tag (main is protected), `scripts/verify-version.sh` checks the tag.
Write user-facing changes under `## [Unreleased]` in `CHANGELOG.md` before releasing —
`scripts/release-notes.sh` turns that section into the release notes in UpdateHub.

## Code signing

Signing is **off by default** (no secrets are committed). Configure it when you
have certificates — unsigned builds still install but trigger OS warnings
(SmartScreen on Windows, Gatekeeper on macOS).

### Windows (Authenticode)

A timestamp URL and SHA-256 digest are already set in `tauri.conf.json`
(`bundle.windows`); only a certificate is missing. **The release workflow is
already wired** — to sign, add two repository secrets:

| Secret | Value |
|--------|-------|
| `WINDOWS_CERTIFICATE` | base64 of your code-signing `.pfx` (`certutil -encode cert.pfx out.b64`, or `base64 -w0 cert.pfx`) |
| `WINDOWS_CERTIFICATE_PASSWORD` | the `.pfx` password |

The `Configure Windows code signing` step imports the PFX into the runner's cert
store and injects its thumbprint into `tauri.conf.json`, so the bundler signs the
MSI and NSIS installers. With the secrets **absent**, the step no-ops and the
build is unsigned (still installable, with a SmartScreen prompt). Nothing secret
is ever committed; the runner is ephemeral.

> **Cert type & reputation:** a standard **OV** cert signs but SmartScreen still
> warns until the binary builds reputation; an **EV** cert (or Azure Trusted
> Signing) is trusted immediately. Either way, get the cert later and just add the
> secrets — no code change needed.

**Signing locally** (optional): set `bundle.windows.certificateThumbprint` to a
cert in your local store, or a custom `signCommand` for HSM / Azure Trusted
Signing, then `cargo tauri build`. Never commit a `.pfx` or its password.

### macOS (sign + notarize)

`tauri-action` and `cargo tauri build` pick these up from the environment:

| Variable | Purpose |
|----------|---------|
| `APPLE_CERTIFICATE` / `APPLE_CERTIFICATE_PASSWORD` | base64 `.p12` + its password |
| `APPLE_SIGNING_IDENTITY` | e.g. `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID` / `APPLE_PASSWORD` / `APPLE_TEAM_ID` | app-specific password for notarization |

With these set, the `.app`/`.dmg` are signed and submitted to Apple's notary
service automatically.

### Linux

No code signing. AppImages may optionally be GPG-signed; `.deb` integrity is
covered by repository signing if you publish to an APT repo.

## CI release workflow

The repository lives on the self-hosted Forgejo (`elerdir/goldfish`); GitHub is only a
mirror and its Actions are not used.

1. **Dispatch** (https://dispatch.niderle.cz) starts `.forgejo/workflows/dispatch.yml` with
   version + platforms. `release-bot` pushes the tag with the version bump.
2. The same run builds the Windows installers on the Windows runner (VM on the NUC) via the
   composite action `.forgejo/actions/windows-installer`: `cargo tauri build --bundles msi,nsis`
   with the updater signature, then uploads MSI and NSIS to **UpdateHub** as a draft.
3. **Publish** the draft in UpdateHub (`/apps/goldfish`) — only then the in-app updater and
   www.niderle.cz offer the version.

`release.yml` covers a manually pushed tag and retries (`workflow_dispatch` with a tag).
macOS and Linux builds return once their runners exist.

### Updater signing key

The in-app updater (Settings → Updates) accepts only builds signed with the minisign key
whose public half is in `tauri.conf.json` → `plugins.updater.pubkey`.
`scripts/new-signing-key.ps1` creates `%USERPROFILE%\.tauri\goldfish.key` (+ `.pub`) and a
DPAPI-protected password; its `-CopyKey` / `-CopyPassword` switches put them on the
clipboard for the Forgejo secrets `TAURI_SIGNING_PRIVATE_KEY` /
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. **Losing or replacing the key means installed copies
reject every future update.** Local builds without the key use
`crates/goldfish-tauri/tauri.nosign.conf.json` (no updater artifacts).

## Reproducibility & integrity

- The release profile is deterministic-leaning (`lto = "thin"`, `codegen-units = 1`,
  `strip = "symbols"`, `panic = "abort"`).
- Publish SHA-256 checksums alongside the installers so users can verify downloads.
