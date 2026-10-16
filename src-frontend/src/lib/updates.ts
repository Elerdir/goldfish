import { useSyncExternalStore } from "react";

/**
 * In-app updates from UpdateHub (Tauri updater plugin: endpoint + public key in
 * tauri.conf.json → plugins.updater). Signature verification happens in the Rust
 * plugin; the frontend only drives the flow.
 *
 * The store is framework-agnostic (injected operations, testable without Tauri);
 * React subscribes through {@link useUpdates}. Each window has its own instance:
 * the main window checks silently on startup and shows a dot on the settings
 * button, the settings window offers check / install / restart.
 */

export type UpdateStatus =
    | "idle"
    | "checking"
    | "up_to_date"
    | "available"
    | "downloading"
    | "ready"
    | "error";

export interface UpdateState {
    status: UpdateStatus;
    /** Version on offer (status available / downloading / ready). */
    version: string | null;
    /** Release notes from UpdateHub (CHANGELOG section). */
    notes: string | null;
    /** Download progress 0–100, null when the size is unknown. */
    progress: number | null;
    /** Error message for status "error". */
    error: string | null;
}

/** A pending update as returned by the updater plugin. */
export interface PendingUpdate {
    version: string;
    body?: string | null;
    downloadAndInstall(onEvent?: (event: DownloadEvent) => void): Promise<void>;
}

export type DownloadEvent =
    | { event: "Started"; data: { contentLength?: number } }
    | { event: "Progress"; data: { chunkLength: number } }
    | { event: "Finished" };

export interface UpdateOps {
    check(): Promise<PendingUpdate | null>;
    relaunch(): Promise<void>;
}

const INITIAL: UpdateState = {
    status: "idle",
    version: null,
    notes: null,
    progress: null,
    error: null,
};

export class UpdateStore {
    readonly #ops: UpdateOps;
    #state: UpdateState = INITIAL;
    #pending: PendingUpdate | null = null;
    readonly #listeners = new Set<() => void>();

    constructor(ops: UpdateOps) {
        this.#ops = ops;
    }

    getSnapshot = (): UpdateState => this.#state;

    subscribe = (listener: () => void): (() => void) => {
        this.#listeners.add(listener);
        return () => this.#listeners.delete(listener);
    };

    /**
     * Asks UpdateHub for a newer version. `silent` (startup check) never surfaces
     * errors — offline or a down server must not bother the user.
     */
    async check(silent = false): Promise<void> {
        if (this.#busy()) return;
        this.#set({ ...INITIAL, status: "checking" });
        try {
            const update = await this.#ops.check();
            this.#pending = update;
            this.#set(
                update
                    ? { ...INITIAL, status: "available", version: update.version, notes: update.body ?? null }
                    : { ...INITIAL, status: silent ? "idle" : "up_to_date" },
            );
        } catch (err) {
            this.#pending = null;
            this.#set(silent ? INITIAL : { ...INITIAL, status: "error", error: messageOf(err) });
        }
    }

    /** Downloads and installs the pending update; the app then needs a restart. */
    async install(): Promise<void> {
        const update = this.#pending;
        if (!update || this.#state.status !== "available") return;
        let total = 0;
        let received = 0;
        this.#set({ ...this.#state, status: "downloading", progress: null, error: null });
        try {
            await update.downloadAndInstall((e) => {
                if (e.event === "Started") {
                    total = e.data.contentLength ?? 0;
                } else if (e.event === "Progress") {
                    received += e.data.chunkLength;
                    if (total > 0) {
                        this.#set({ ...this.#state, progress: Math.min(100, Math.round((received / total) * 100)) });
                    }
                }
            });
            this.#set({ ...this.#state, status: "ready", progress: 100 });
        } catch (err) {
            this.#set({ ...this.#state, status: "error", progress: null, error: messageOf(err) });
        }
    }

    async relaunch(): Promise<void> {
        if (this.#state.status !== "ready") return;
        await this.#ops.relaunch();
    }

    #busy(): boolean {
        const s = this.#state.status;
        return s === "checking" || s === "downloading" || s === "ready";
    }

    #set(next: UpdateState): void {
        this.#state = next;
        for (const listener of this.#listeners) listener();
    }
}

function messageOf(err: unknown): string {
    if (err instanceof Error) return err.message;
    return typeof err === "string" ? err : "unknown error";
}

/** Real operations — the plugins are loaded lazily so tests and the browser never touch them. */
const tauriOps: UpdateOps = {
    async check() {
        const { check } = await import("@tauri-apps/plugin-updater");
        return check();
    },
    async relaunch() {
        const { relaunch } = await import("@tauri-apps/plugin-process");
        await relaunch();
    },
};

/** Per-window store instance. */
export const updates = new UpdateStore(tauriOps);

export function useUpdates(): UpdateState {
    return useSyncExternalStore(updates.subscribe, updates.getSnapshot);
}
