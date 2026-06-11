import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

// The release binary produced by `cargo build --release -p goldfish-tauri`.
// In a Cargo workspace the target dir lives at the workspace root.
const binaryName = process.platform === "win32" ? "goldfish.exe" : "goldfish";
const application = path.join(repoRoot, "target", "release", binaryName);

// `tauri-driver` (installed via `cargo install tauri-driver`) proxies WebDriver
// to the platform webview driver (msedgedriver on Windows, WebKitWebDriver on
// Linux). Ensure the matching native driver is on PATH.
let tauriDriver: ChildProcess | undefined;

export const config: WebdriverIO.Config = {
    runner: "local",
    specs: ["./specs/**/*.e2e.ts"],
    maxInstances: 1,
    capabilities: [
        {
            browserName: "wry",
            // @ts-expect-error — tauri-driver-specific capability.
            "tauri:options": { application },
        },
    ],
    framework: "mocha",
    mochaOpts: { ui: "bdd", timeout: 60_000 },
    reporters: ["spec"],
    logLevel: "info",
    hostname: "127.0.0.1",
    port: 4444,

    // Build the app in release before the suite so the binary above exists.
    onPrepare: () => {
        const built = spawnSync("cargo", ["build", "--release", "-p", "goldfish-tauri"], {
            cwd: repoRoot,
            stdio: "inherit",
        });
        if (built.status !== 0) throw new Error("cargo build failed; cannot run e2e");
    },

    beforeSession: () => {
        tauriDriver = spawn(path.join(os.homedir(), ".cargo", "bin", "tauri-driver"), [], {
            stdio: [null, process.stdout, process.stderr],
        });
    },

    afterSession: () => {
        tauriDriver?.kill();
    },
};
