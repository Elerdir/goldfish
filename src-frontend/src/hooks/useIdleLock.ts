import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";

import { ACTIVITY_EVENT, isTauri } from "@/lib/tauri";

interface IdleLockOptions {
    /** Idle minutes before locking; 0 disables the idle timer. */
    minutes: number;
    /** Also lock immediately when the window loses focus. */
    lockOnBlur: boolean;
    /** Stable callback that locks the vault. */
    onLock: () => void;
}

const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "touchstart", "scroll"] as const;

/** How often the sleep watchdog ticks. */
const WATCHDOG_TICK_MS = 15_000;
/**
 * If two watchdog ticks are further apart than this, time has "jumped" — the
 * machine almost certainly slept/hibernated (frozen timers) rather than merely
 * backgrounding (which throttles timers to roughly once a minute). We then lock,
 * so a vault left unlocked when the lid closes is sealed on resume — regardless
 * of the idle-timeout setting.
 */
const SLEEP_GAP_MS = 90_000;
/**
 * Grace period after a blur before locking (when lock-on-blur is on). Activity in
 * one of our own sub-windows pings within this window and cancels the lock, so
 * opening Settings / the entry editor doesn't lock the vault behind it.
 */
const BLUR_GRACE_MS = 1500;

/**
 * Locks the vault after a period of user inactivity (and optionally on window
 * blur), and always locks on resume from system sleep. Mount this only while the
 * vault is unlocked. `onLock` must be stable (e.g. wrapped in `useCallback`) or
 * the timer resets every render.
 */
export function useIdleLock({ minutes, lockOnBlur, onLock }: IdleLockOptions): void {
    useEffect(() => {
        const idleMs = minutes > 0 ? minutes * 60_000 : 0;
        let timer: number | undefined;
        let blurTimer: number | undefined;

        const clearBlur = () => {
            if (blurTimer !== undefined) {
                window.clearTimeout(blurTimer);
                blurTimer = undefined;
            }
        };

        const reset = () => {
            clearBlur(); // any activity (incl. from a sub-window) cancels a pending blur-lock
            if (idleMs <= 0) return;
            if (timer !== undefined) window.clearTimeout(timer);
            timer = window.setTimeout(onLock, idleMs);
        };

        // Lock shortly after blur (not instantly), so opening our own sub-window —
        // which immediately pings activity — cancels it.
        const onBlur = () => {
            if (!lockOnBlur) return;
            clearBlur();
            blurTimer = window.setTimeout(onLock, BLUR_GRACE_MS);
        };
        const onFocus = () => clearBlur();

        // Sleep watchdog: detect a wall-clock jump between ticks. Always on —
        // locking on resume from suspend is a safety measure independent of the
        // idle timeout (which uses a timer that freezes during sleep anyway).
        let lastTick = Date.now();
        const watchdog = window.setInterval(() => {
            const now = Date.now();
            if (now - lastTick > SLEEP_GAP_MS) onLock();
            lastTick = now;
        }, WATCHDOG_TICK_MS);

        if (idleMs > 0) {
            for (const evt of ACTIVITY_EVENTS) {
                window.addEventListener(evt, reset, { passive: true });
            }
            reset();
        }
        window.addEventListener("blur", onBlur);
        window.addEventListener("focus", onFocus);

        // Activity in a sub-window (add/edit entry, settings) also counts as
        // activity here, so editing in another window doesn't trigger auto-lock.
        const activity = isTauri() ? listen(ACTIVITY_EVENT, reset) : null;

        return () => {
            if (timer !== undefined) window.clearTimeout(timer);
            clearBlur();
            window.clearInterval(watchdog);
            for (const evt of ACTIVITY_EVENTS) {
                window.removeEventListener(evt, reset);
            }
            window.removeEventListener("blur", onBlur);
            window.removeEventListener("focus", onFocus);
            if (activity) void activity.then((unlisten) => unlisten());
        };
    }, [minutes, lockOnBlur, onLock]);
}
