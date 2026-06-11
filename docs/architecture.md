# Architecture

## Layers

```
┌──────────────────────────────────────────────┐
│  src-frontend (React + TS + Vite + Tailwind) │   UI shell
└────────────────┬─────────────────────────────┘
                 │ Tauri IPC (JSON, typed wrappers)
┌────────────────▼─────────────────────────────┐
│  goldfish-tauri (binary)                     │   commands → use cases
└────────────────┬─────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────┐
│  goldfish-infrastructure                     │   adapters
│  • SQLiteEntryRepository (SQLCipher)         │
│  • OsKeyStore (Win Hello / Touch ID / fprintd)│
│  • HibpClient                                │
│  • CsvImporter (Bitwarden / KeePassXC / 1Pwd) │
└────────────────┬─────────────────────────────┘
                 │ depends on traits in ↓
┌────────────────▼─────────────────────────────┐
│  goldfish-application                        │   use cases + ports (traits)
└────────────────┬─────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────┐
│  goldfish-domain                             │   pure types, invariants
└──────────────────────────────────────────────┘

           ┌──────────────────────┐
           │  goldfish-crypto     │   audit-isolated leaf
           └──────────────────────┘
           Used by infrastructure (and crypto-aware adapters)
           via traits defined in `application::ports`.
```

## Dependency rule

Dependencies point **inward**. Outer layers know about inner; inner layers
know **nothing** about outer.

| Crate                       | May depend on                                       |
|-----------------------------|-----------------------------------------------------|
| `goldfish-domain`           | std, leaf utility crates only                       |
| `goldfish-application`      | `domain`, leaf utility crates                       |
| `goldfish-crypto`           | std, RustCrypto crates (no upper-layer crates)      |
| `goldfish-infrastructure`   | `domain`, `application`, `crypto`, adapter crates   |
| `goldfish-tauri`            | all of the above                                    |

A clippy lint or CI rule prohibits, e.g., `domain → rusqlite`.

## What lives where

### `goldfish-domain`
- `Entry`, `EntryDraft`, `EntryId` — validated value types
- `PlaintextSecret` — `Debug`-redacting, `Drop`-zeroizing secret wrapper
- `VaultMetadata`, `KdfParams` — vault-level state
- `DomainError` — invariant violations

### `goldfish-application`
- Use cases: `CreateVault`, `UnlockVault`, `AddEntry`, `UpdateEntry`,
  `DeleteEntry`, `ListEntries`, `GeneratePassword`, `CheckHibp`,
  `ImportCsv`, `ExportEncrypted` (phased — Phase 0 has only module shape)
- Ports: `EntryRepository`, `VaultMetadataRepository`, `OsKeyStore`,
  `Clock`, `SecureRandom`
- `ApplicationError`

### `goldfish-crypto`
- `kdf` — Argon2id
- `aead` — XChaCha20-Poly1305 (`seal`, `open` with AAD)
- `mac` — HMAC-SHA256 (verifier)
- `derive` — HKDF-SHA256 subkey derivation
- `rng` — OS-CSPRNG wrappers

### `goldfish-infrastructure`
- `sqlite` — SQLCipher-backed `EntryRepository` + `VaultMetadataRepository`
- `keystore` (Phase 9) — `OsKeyStore` per platform
- `hibp` (Phase 10) — k-anonymity client
- `importers` (Phase 11)

### `goldfish-tauri`
- Tauri commands; each `#[tauri::command]` delegates to exactly one use case
- App state holding the unlocked DEK is in a `parking_lot::Mutex<Option<UnlockedVault>>`
- Window setup, tracing init, plugin registration

## State management & locking

The unlocked DEK lives in `goldfish-tauri` app state — never serialized, never
sent to the frontend. The frontend only sees:
- Plaintext metadata (title/url/description/app_name)
- Decrypted credential payloads only when the user explicitly requests a single
  entry's detail view; cleared from the frontend as soon as the view unmounts

The "lock" operation drops the DEK (which is `Zeroizing`) and clears any
front-end caches via React Query's `queryClient.clear()`.

## Crypto key hierarchy

See `docs/threat-model.md`.
