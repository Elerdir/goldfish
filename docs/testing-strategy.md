# Testing strategy

Tests live at four altitudes. Each one buys a specific kind of confidence; we
add them when a layer actually carries logic worth checking, not as
boilerplate.

## 1. Unit tests — `crates/<name>/src/**/tests`

Co-located `#[cfg(test)] mod tests` blocks. Fast (< 1 s per crate), no I/O,
no async, no fixtures. Test pure logic and invariants of the module they sit
next to.

| Crate | Status | Coverage philosophy |
|---|---|---|
| `goldfish-domain` | **Active** | Validation paths (happy + every error branch), boundary lengths (max, max+1, empty, trimmed), redaction guarantees, Unicode safety. UUID v7 monotonicity. KDF param invariants. |
| `goldfish-application` | **Active** | Use cases — each spawned with port mocks (in-memory `EntryRepository`, fake `Clock`, in-memory keystore) + real crypto. One test per branch. Includes import/encrypted-export round-trips and the unlock backoff throttle. |
| `goldfish-crypto` | **Active** | **KAT (known-answer tests)** against published RFC test vectors for Argon2id, XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256. Round-trip + tamper rejection + wrong-key rejection. Property tests via `proptest` over plaintext lengths and AAD shapes. Export-container framing/tamper tests. |
| `goldfish-infrastructure` | **Active** | Repo CRUD on a tempfile SQLCipher DB, encryption-at-rest assertion, optimistic-lock conflict. |
| `goldfish-tauri` | Intentionally none | Tauri commands are thin pass-throughs over the well-tested application layer — exercised manually / via the e2e harness, not unit-tested. |

Total: **145** Rust tests across the workspace.

## 2. Integration tests — `crates/<name>/tests/*.rs`

Each file is its own binary crate; it can only import the parent crate's
**public API**. This is the boundary that other crates (and external users)
will see.

| Crate | Status | What lives here |
|---|---|---|
| `goldfish-domain` | **Active** — `tests/entry_draft_builder.rs` | Full `EntryDraft::new(...).with_description(...).with_url(...)` chain. Verifies that the public surface composes cleanly without leaking internal types. |
| `goldfish-application` | **Active** | Builder-chain composition over the public surface. |
| `goldfish-infrastructure` | **Active** | End-to-end repo tests against a real tempfile SQLCipher DB, including create→lock→unlock persistence and cryptographic isolation between vaults. |

## 3. Cross-crate integration — `crates/goldfish-tauri/tests/*.rs`

Tests that wire **multiple production adapters** together: real
`SqliteEntryRepository` + real crypto + the `UnlockVault` / `AddEntry` /
`ListEntries` use cases. No Tauri runtime — just the Rust side of the boundary.

Lands when the first vertical slice is complete (Phase 4).

## 4. Frontend unit / component tests — `src-frontend/src/**/*.test.{ts,tsx}`

Run with **vitest** + **React Testing Library** (jsdom), via `pnpm test` in CI.
Two layers:

- **Pure logic**: IPC error narrowing (`asCommandError`), the client-side
  password-strength heuristic fallback (`estimateStrength` outside Tauri).
- **Hooks & providers** (jsdom): `useIdleLock` (idle timeout, activity reset,
  blur grace + cancel), `SettingsProvider` (clamp/sanitize/persist),
  `ThemeProvider` (class application + persistence), `VaultProvider` (the
  loading → onboarding/locked/unlocked state machine, including reflecting an
  already-unlocked backend on init), and `Dialog` accessibility (focus enters on
  open, ESC closes, focus is restored on close). Tauri IPC is mocked.

`setup.ts` stubs `matchMedia` (absent in jsdom). Component coverage focuses on
behavior with real failure modes; trivial presentational components are left to
the e2e smoke.

## 5. End-to-end (Tauri runtime) — **scaffolded**

A WebdriverIO + `tauri-driver` harness lives in `e2e/` (see `e2e/README.md`). The
smoke spec onboards a fresh vault and asserts the app reaches the unlocked state,
driving the real binary (boot → IPC → SQLCipher → state transition). It needs a
native WebDriver (msedgedriver / WebKitWebDriver) and a display, so it runs on
demand: locally via `cd e2e && npm run test:e2e`, or in CI via the manual
`e2e.yml` workflow (Linux + xvfb), kept **non-blocking**.

**Status: scaffolded, not yet wired into the blocking gate.** The harness and a
runnable smoke exist; promote `e2e.yml` to a schedule once validated on a runner.
Broader runtime coverage (biometrics, tray, screen-capture, clipboard, installers)
is inherently hardware/OS-bound and is verified against `docs/qa-checklist.md`.

## What we deliberately don't test (yet)

- **`goldfish-tauri::ping`** — its body is `"pong"`. Testing it adds noise
  without catching a realistic regression. Phase 0 frontend manually
  confirms the IPC channel works (verified during scaffold).
- **Tauri's own plumbing** — `Builder::default()` etc. Tauri's own test suite
  covers that; we'd be re-asserting framework behavior.
- **Adapter shells that just delegate** — we test what they delegate to, not
  the one-line forwarding.

## Conventions

- Test names describe behavior, not implementation: `draft_rejects_empty_title`
  not `test_new_empty_title`.
- Each test asserts **one** behavior. If the name needs an "and," split it.
- No sleeping for timing-dependent tests except the UUID v7 monotonicity one
  (which is fundamentally time-bound).
- Never compare error variants by string match — use `matches!(err,
  DomainError::Foo { .. })` so future error refactors don't ghost-pass tests.
- Crypto tests must include negative paths (wrong key, tampered ciphertext,
  modified AAD) — positive-only would let real bugs through.
