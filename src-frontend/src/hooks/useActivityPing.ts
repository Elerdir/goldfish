import { useEffect } from "react";

import { emitActivity, isTauri } from "@/lib/tauri";

const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"] as const;
/** Throttle so we emit at most one ping per this many ms. */
const THROTTLE_MS = 5000;

/**
 * While mounted, pings the main window on user activity so its idle auto-lock
 * doesn't fire while the user is busy in this sub-window. If the user is idle
 * here too (no events), no pings are sent and the vault locks normally.
 */
export function useActivityPing(): void {
    useEffect(() => {
        if (!isTauri()) return undefined;
        let last = 0;
        const ping = () => {
            const now = Date.now();
            if (now - last < THROTTLE_MS) return;
            last = now;
            void emitActivity();
        };
        ping(); // initial ping on open
        for (const evt of ACTIVITY_EVENTS) {
            window.addEventListener(evt, ping, { passive: true });
        }
        return () => {
            for (const evt of ACTIVITY_EVENTS) {
                window.removeEventListener(evt, ping);
            }
        };
    }, []);
}
