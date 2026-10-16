import { describe, expect, it, vi } from "vitest";

import { UpdateStore, type DownloadEvent, type PendingUpdate, type UpdateOps } from "@/lib/updates";

function pending(version = "1.1.0", events: DownloadEvent[] = [], fail?: Error): PendingUpdate {
    return {
        version,
        body: "notes",
        downloadAndInstall: vi.fn((onEvent?: (e: DownloadEvent) => void) => {
            for (const e of events) onEvent?.(e);
            return fail ? Promise.reject(fail) : Promise.resolve();
        }),
    };
}

function store(check: UpdateOps["check"], relaunch = vi.fn(() => Promise.resolve())) {
    return { s: new UpdateStore({ check, relaunch }), relaunch };
}

describe("UpdateStore", () => {
    it("reports an available update with version and notes", async () => {
        const { s } = store(() => Promise.resolve(pending("1.2.3")));
        await s.check();
        expect(s.getSnapshot()).toMatchObject({ status: "available", version: "1.2.3", notes: "notes" });
    });

    it("reports up to date on a manual check, stays idle on a silent one", async () => {
        const { s } = store(() => Promise.resolve(null));
        await s.check();
        expect(s.getSnapshot().status).toBe("up_to_date");
        await s.check(true);
        expect(s.getSnapshot().status).toBe("idle");
    });

    it("surfaces errors only on a manual check", async () => {
        const { s } = store(() => Promise.reject(new Error("offline")));
        await s.check(true);
        expect(s.getSnapshot()).toMatchObject({ status: "idle", error: null });
        await s.check();
        expect(s.getSnapshot()).toMatchObject({ status: "error", error: "offline" });
    });

    it("tracks download progress and ends ready to restart", async () => {
        const progress: number[] = [];
        const { s } = store(() =>
            Promise.resolve(
                pending("1.1.0", [
                    { event: "Started", data: { contentLength: 200 } },
                    { event: "Progress", data: { chunkLength: 50 } },
                    { event: "Progress", data: { chunkLength: 150 } },
                    { event: "Finished" },
                ]),
            ),
        );
        await s.check();
        s.subscribe(() => {
            const p = s.getSnapshot().progress;
            if (p !== null) progress.push(p);
        });
        await s.install();
        expect(progress).toEqual([25, 100, 100]);
        expect(s.getSnapshot().status).toBe("ready");
    });

    it("keeps the version and reports a failed install", async () => {
        const { s } = store(() => Promise.resolve(pending("1.1.0", [], new Error("signature mismatch"))));
        await s.check();
        await s.install();
        expect(s.getSnapshot()).toMatchObject({
            status: "error",
            version: "1.1.0",
            error: "signature mismatch",
        });
    });

    it("relaunches only once the update is installed", async () => {
        const { s, relaunch } = store(() => Promise.resolve(pending()));
        await s.relaunch();
        expect(relaunch).not.toHaveBeenCalled();
        await s.check();
        await s.install();
        await s.relaunch();
        expect(relaunch).toHaveBeenCalledOnce();
    });

    it("ignores a second check while one is running", async () => {
        let resolve: (u: PendingUpdate | null) => void = () => {};
        const check = vi.fn(() => new Promise<PendingUpdate | null>((r) => (resolve = r)));
        const { s } = store(check);
        const first = s.check();
        await s.check();
        resolve(null);
        await first;
        expect(check).toHaveBeenCalledOnce();
    });
});
