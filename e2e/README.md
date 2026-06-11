# Goldfish end-to-end tests

A WebdriverIO + [`tauri-driver`](https://v2.tauri.app/develop/tests/webdriver/)
harness that drives the **built** desktop app like a user. It is intentionally
separate from the frontend unit tests (`src-frontend`, Vitest) and from the
workspace gate — it needs a native WebDriver, a built binary, and a display, so
it is run on demand, not in the default CI gate.

> Status: scaffold. The config and smoke spec are ready to run but have **not**
> been executed in CI yet (they require the platform WebDriver below). Wire them
> into a dedicated, non-blocking CI job once validated locally.

## Prerequisites

- **tauri-driver**: `cargo install tauri-driver`
- **Platform WebDriver** on `PATH`:
  - **Windows**: `msedgedriver.exe` matching your installed Edge/WebView2
    (`https://developer.microsoft.com/microsoft-edge/tools/webdriver/`).
  - **Linux**: `WebKitWebDriver` (package `webkit2gtk-driver`) + `xvfb` for
    headless runs.
  - macOS: WebView (WKWebView) is **not** supported by tauri-driver yet.
- Node deps: `cd e2e && npm install` (or `pnpm install` — the driver build
  scripts are pre-approved in `pnpm-workspace.yaml`)

## Run

```bash
# from the repo root
cd e2e
npm install            # first time only
npm run test:e2e       # builds the app (cargo build --release) then runs specs
```

On Linux headless: `xvfb-run -a npm run test:e2e`.

## Clean profile

The smoke spec onboards a **new** vault, so it needs an empty app-data profile.
Before a deterministic run, remove the vault for identifier `com.goldfish.desktop`:

- **Windows**: `%APPDATA%\com.goldfish.desktop`
- **Linux**: `~/.local/share/com.goldfish.desktop`

If a vault already exists, the spec logs a skip (it can't know the master
password).

## Extending

Lock / add-entry / edit flows need stable selectors. Add `data-testid`
attributes to those controls (e.g. the lock button, the "add entry" button) and
target them with `$('[data-testid="..."]')`, then assert the resulting screen.
