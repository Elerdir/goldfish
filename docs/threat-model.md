# Threat model

## Assets

| Asset                | Why it matters                                |
|----------------------|-----------------------------------------------|
| Master password      | Bootstraps all crypto. Single point of compromise. |
| KEK (key-encryption-key) | Derived from master password; encrypts the DEK. |
| DEK (data-encryption-key) | Encrypts every credential. |
| Vault file on disk   | If readable, attacker has the entire ciphertext corpus. |
| Plaintext credentials in memory | Sensitive while vault is unlocked. |
| Process memory       | Could be dumped (LSASS-style attack, crash dump). |

## Trust boundaries

```
┌───────────────────────────────────────────┐
│ User                                      │   trusted
└──────────────┬────────────────────────────┘
               │ keyboard / biometric prompt
┌──────────────▼────────────────────────────┐
│ Goldfish process (Rust + Webview)         │   semi-trusted
│  ┌────────────────────────────────────┐   │
│  │ Webview (renderer, isolated)       │   │   least-trusted
│  └────────────────────────────────────┘   │
└──────────────┬────────────────────────────┘
               │ filesystem
┌──────────────▼────────────────────────────┐
│ Disk (SQLCipher-encrypted vault)          │   untrusted-at-rest
└───────────────────────────────────────────┘

External: HIBP API (k-anonymity, prefix only)  — untrusted, opt-in
```

## Adversaries

1. **Offline attacker with vault file** — got the SQLCipher DB but not the master
   password. Must brute-force Argon2id at m=64 MiB, t=3 — economically expensive.
2. **Online attacker with live process** — running malware that can read memory.
   Goal: minimize plaintext residency (zeroize on drop, lock on idle/suspend).
3. **Shoulder surfer / clipboard sniffer** — auto-clear clipboard after N s; lock
   on focus loss (optional).
4. **Malicious / compromised webview content** — strict CSP, no remote URLs in
   `src-frontend`; Tauri capabilities list scoped to bare minimum.
5. **Network attacker** — sees HIBP request prefixes only (k-anonymity); pinned
   TLS via `rustls-tls`. Otherwise no network calls.

## Key hierarchy

```
Master Password (user-entered, never persisted)
        │
        │  Argon2id(memory_kib=65536, iterations=3, parallelism=1, salt=16B)
        ▼
KEK  ┄ 32 bytes ┄ kept in Zeroizing<[u8; 32]>, lives only while unlocked
        │
        ├── HMAC-SHA256(KEK, "goldfish-unlock-verifier")  →  stored as verifier (32 B)
        │                                                    used for constant-time master-password check
        │
        └── XChaCha20-Poly1305-encrypted DEK
                │  AAD = "goldfish-dek-v1" + schema_version
                │  Nonce = 24 random bytes (per vault, regenerated on master-password change)
                ▼
            DEK ┄ 32 bytes ┄ random at vault creation, kept in Zeroizing<[u8; 32]>
                │
                └── HKDF-SHA256(DEK, salt=entry_id, info="goldfish-entry-v1")
                        ▼
                    per-entry subkey
                        │
                        ▼
                XChaCha20-Poly1305(subkey, nonce=24 random bytes per entry,
                                   AAD = entry_id || u32(version))
                        ▼
                ciphertext_username, ciphertext_password, ciphertext_notes, ciphertext_totp
                        │
                        ▼
                Stored inside SQLCipher-encrypted SQLite (page-level AES-256-CBC + HMAC-SHA512)
```

### Why two layers (SQLCipher + per-entry AEAD)?

Defence in depth.
- **SQLCipher alone** protects the file at rest — but if a process dumps SQLite pages
  while open, plaintext leaks.
- **Per-entry AEAD alone** doesn't hide metadata patterns or table structure on disk.
- **Both**: an attacker has to break both layers AND know two distinct key chains
  (DB key vs entry subkey), and AAD binds each ciphertext to its `entry_id +
  version` so cut-and-paste of ciphertexts across entries fails authentication.

## Rules

- **Master password never leaves Rust.** Frontend passes it once via IPC; Rust
  derives KEK immediately and zeroizes the input string.
- **No secrets in logs.** `tracing` subscriber is configured with redaction; any
  field carrying secret material uses `PlaintextSecret` whose `Debug` is redacted.
- **Constant-time comparisons** for the verifier (`subtle::ConstantTimeEq`).
- **Rate limit unlock attempts** *(implemented — `application::throttle::UnlockThrottle`)*:
  exponential backoff (1 s → 2 s → 4 s → … → max 60 s) per process on the
  master-password path, reset only on a successful unlock. The check runs before
  Argon2id, so throttled attempts cost no work. Biometric unlock is not throttled
  here — it is gated by the OS verifier, which has its own anti-hammering.
- **Auto-lock**: after N minutes idle (default 5); on system suspend; on
  display lock (best-effort per OS).
- **Clipboard auto-clear**: configurable (default 20 s); on lock; on app exit.
  *Residual:* OS clipboard history / cloud-clipboard sync (e.g. Windows Win+V) can
  capture a copied secret before the timed clear. Suppressing that needs raw
  per-platform clipboard-format flags (bypassing the clipboard plugin); it is a
  documented future hardening, deliberately not done yet to avoid regressing the
  working auto-clear path.
- **KDF calibration + upgrade**: new vaults calibrate Argon2id to ≈250 ms on the
  device (never below the OWASP floor); unlocking a vault whose stored cost is
  below the current floor transparently re-wraps the DEK under stronger params
  (`application::throttle` aside, see `VaultService::maybe_upgrade_kdf`).
- **Memory hygiene (frontend)**: decrypted entries cross to the webview only on
  demand and are never cached (`gcTime: 0`); the query cache is evicted the moment
  a detail/edit dialog closes, minimizing plaintext residency in renderer memory.
- **Supply chain**: CI runs `cargo deny check advisories bans sources` against the
  RustSec database; accepted (unmaintained/transitive) advisories are pinned with
  rationale in `deny.toml`.
- **Data durability**: SQLCipher runs in WAL mode with `synchronous = NORMAL`
  (power-loss safe), `PRAGMA quick_check` on open (corruption/wrong-key detection),
  rolling encrypted snapshots under `backups/`, and a single-instance lock so two
  processes never write the same vault file.
- **Strict CSP**: `default-src 'self'`; only `connect-src` allows the HIBP API
  endpoint (and only when the feature is enabled).
- **Screen-capture exclusion** *(Windows, best-effort)*: every Goldfish window —
  main, settings, logs and the entry editor — sets `WDA_EXCLUDEFROMCAPTURE` via
  `SetWindowDisplayAffinity`, so screen recorders, screenshots and Teams/Zoom
  screen-shares render it blank. The main window is excluded natively at startup;
  each sub-window calls the `protect_window` command on mount. No-op on Windows
  before 10 2004 and on non-Windows platforms (macOS would need
  `NSWindow.sharingType = .none`).
- **`unsafe` is forbidden in the domain / application / crypto crates** (lint
  `unsafe_code = "forbid"`) and *denied* in infrastructure and the Tauri shell,
  where it is permitted only in narrowly-scoped, `// SAFETY:`-documented FFI: the
  OS biometric gate (Windows Hello / macOS Touch ID) and the screen-capture
  exclusion above.
- **Capabilities**: Tauri capabilities are an explicit allow-list. Never use
  wildcards; add one permission per feature as it lands.

## Biometric unlock (Phase 9)

Optional convenience: after a master-password unlock, the user may enable
biometric unlock.

```
enable:  random BPK (32B) ──┐
         DEK ──XChaCha20-Poly1305(BPK)──▶ wrapped_dek + nonce  → stored in sidecar (VaultMetadata.biometric)
         BPK ──────────────────────────▶ OS credential store (Credential Manager / Keychain / Secret Service)

unlock:  OS consent prompt:
             • Windows — Windows Hello (UserConsentVerifier)
             • macOS   — Touch ID (LocalAuthentication / LAContext)
             │ verified
             ▼
         retrieve BPK from credential store
             │
         unwrap DEK with BPK ──▶ VaultKeyset ──▶ open vault
```

**Security level — convenience, not a hardware-bound factor.** The BPK lives in
the OS credential store (DPAPI / Keychain / Secret Service, i.e. user-session
protected) and the prompt is a *consent gate*. Code running as the same OS user
could, in principle, read the BPK without the prompt. The master password remains
the cryptographic root; biometric unlock only avoids retyping it. A future
hardening would bind the BPK to a TPM/Secure-Enclave key, making it
non-exportable.

- Stealing the sidecar alone never yields the DEK (the BPK is not in it).
- Disabling biometrics deletes the BPK from the keystore and clears the sidecar
  field.
- **Per-device by design.** The BPK never leaves the machine's credential store
  and is *not* part of the encrypted export. Moving a vault to another machine or
  OS (e.g. Windows → macOS) is done via the password-only `.goldfish` export; the
  user simply re-enables biometrics (Touch ID / Windows Hello) on the new device.
- **macOS uses Touch ID only** (`DeviceOwnerAuthenticationWithBiometrics`), so the
  toggle appears only when a biometric is enrolled; users without it fall back to
  the master password. Linux: credential storage works but the biometric gate is
  not yet implemented, so the feature reports itself unavailable there.

## Recovery code (optional)

A user may enable a one-time **recovery code** that can reset a forgotten master
password. Enabling it wraps the DEK a second time under a key derived (Argon2id,
fresh salt) from a freshly generated ~160-bit code; the wrap is stored in the
sidecar (`VaultMetadata.recovery`). Recovering derives that key from the entered
code, unwraps the DEK, then **re-wraps it under a new master password** and
persists the new material. The recovery wrap survives.

```
enable:   random 160-bit code ──Argon2id(salt)──▶ recovery key
          DEK ──XChaCha20-Poly1305(recovery key, AAD = "recovery-dek-v1"‖schema)──▶ stored wrap
          (code shown once, never stored; user prints/saves it)

recover:  code ─▶ recovery key ─▶ unwrap DEK ─▶ re-wrap under NEW master password
```

**Security trade-off (deliberate, opt-in, documented in-app).** Enabling recovery
creates a *second path to the DEK*: the vault's security now also depends on the
secrecy of the recovery code. The code is full-entropy (≈160 bits), so it is not
brute-forceable, but if it leaks the vault is compromised — hence the UI shows it
once with a "store it offline / anyone with it can reset your vault" warning, and
recovery is off by default. The recovery wrap is keyed by a distinct AAD so it
cannot be confused with the master or biometric wraps.

## Encrypted export / backup (Phase 12)

A portable `.goldfish` file lets the user back up or migrate the whole vault. It
is **self-contained**: protected by its own password, decryptable on any device
with nothing but that password — independent of the master password and the OS
keystore.

```
export:  bundle = JSON{ format, version, exported_at, entries[plaintext] }
         export password ──Argon2id(salt=16B random, m/t/p from header)──▶ export key (32B)
         bundle ──XChaCha20-Poly1305(export key, nonce=24B random, AAD = full 64B header)──▶ ciphertext
         file = header(64B: magic‖versions‖algo ids‖KDF params‖salt‖nonce) ‖ ciphertext

import:  parse + authenticate header → re-derive key → AEAD-open → deserialize → import as new entries
```

- **Whole header is the AAD.** Magic, format/algorithm ids, KDF parameters, salt
  and nonce are all authenticated; tampering with any framing byte fails
  decryption (`CryptoError::Decryption`). Malformed/unsupported framing is a
  distinct, non-secret parse error (`InvalidFormat`).
- **Independent password.** The export is not tied to the master password, so a
  backup can be shared or restored without exposing the vault root secret. The UI
  enforces a confirmed minimum-length export password.
- **Plaintext never crosses to the webview.** Both export and import run entirely
  in Rust: the decrypted bundle is built/parsed in the backend, only ciphertext
  is written to (or read from) disk, and the serialized JSON buffer is held in
  zeroizing storage and wiped immediately after sealing.
- **Re-import creates fresh entries** (new id, version 1, current timestamps); ids,
  versions and timestamps are intentionally not carried — the bundle is a
  credential set, not a byte-for-byte vault image.
- **Residual exposure.** Anyone who learns the export password gets every
  credential — the file is exactly as sensitive as the vault. It is the user's
  responsibility to store it safely and choose a strong export password; there is
  no recovery if the export password is lost.

## Out of scope (MVP)

- Browser autofill / native messaging hosts (Phase ≥ 2)
- Cloud sync of any kind (local-first; portable encrypted `.goldfish` export only)
- Mobile builds
- TPM-bound keys (Windows TPM, Apple Secure Enclave directly) — biometric
  unlock uses platform keystore which already leverages these
- Plausible-deniability decoy vaults
