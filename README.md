# Goldfish

> *"Paměť jako akvarijní rybička."* — A local-first, cross-platform password manager that never forgets so you can.

**Stack:** Tauri 2 · Rust (clean architecture, Cargo workspace) · SQLite + SQLCipher · React 19 + TypeScript + Tailwind · Argon2id + XChaCha20-Poly1305 · i18n (en/de/cs) · light/dark/auto theme · biometric unlock (Windows Hello / Touch ID / fprintd).

## Status

MVP feature-complete. Vault create/unlock, entry CRUD, password generator + strength
(zxcvbn), auto-lock & clipboard self-clear, TOTP, HIBP breach check (k-anonymity),
import (Bitwarden / KeePassXC / 1Password), encrypted `.goldfish` export/import, and
biometric unlock (Windows Hello). Packaged as MSI / NSIS / DMG / AppImage.

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md),
[docs/testing-strategy.md](docs/testing-strategy.md), and [docs/packaging.md](docs/packaging.md).

## Repo layout

```
goldfish/
├── Cargo.toml                       workspace root
├── crates/
│   ├── goldfish-domain/             pure domain (no I/O)
│   ├── goldfish-application/        use cases + ports (traits)
│   ├── goldfish-crypto/             audit-isolated crypto primitives
│   ├── goldfish-infrastructure/     SQLite/SQLCipher repo, OS keystore, HIBP
│   └── goldfish-tauri/              binary: Tauri commands → use cases
├── src-frontend/                    React + Vite + TS + Tailwind
└── docs/                            architecture & threat model
```

Dependency direction is strictly inward: `tauri → infrastructure → application → domain`. `crypto` is a leaf — referenced only via ports defined in `application`.

## Dev prerequisites

| Tool         | Version | Why                                                    |
|--------------|---------|--------------------------------------------------------|
| Rust         | ≥ 1.80  | backend                                                |
| Node         | ≥ 20    | frontend tooling                                       |
| pnpm         | ≥ 9     | frontend package manager (via `corepack enable`)        |
| Perl + NASM  | any     | building vendored OpenSSL for `bundled-sqlcipher-vendored-openssl` |
| cargo-tauri  | ≥ 2     | `cargo install tauri-cli --version "^2.0" --locked`     |

## Build & run

```powershell
# 1) backend
cargo check --workspace

# 2) frontend
pnpm --dir src-frontend install
pnpm --dir src-frontend dev

# 3) full app (dev)
cargo tauri dev
```

## Build installers

```powershell
# Windows: MSI + NSIS  →  target\release\bundle\
.\build-installer.bat
```

Other platforms and code signing (Windows Authenticode, macOS notarization) are
documented in [docs/packaging.md](docs/packaging.md). Tagged releases build all
platforms in CI via [`.github/workflows/release.yml`](.github/workflows/release.yml).

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
