import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useIdleLock } from "./useIdleLock";

// The timer/blur callbacks call the external `onLock` (and reset internal
// timers) without touching React state, so advancing timers needs no `act`.
describe("useIdleLock", () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });
    afterEach(() => {
        vi.useRealTimers();
    });

    it("locks after the idle timeout elapses", () => {
        const onLock = vi.fn();
        renderHook(() => useIdleLock({ minutes: 1, lockOnBlur: false, onLock }));
        expect(onLock).not.toHaveBeenCalled();
        vi.advanceTimersByTime(60_000);
        expect(onLock).toHaveBeenCalledTimes(1);
    });

    it("resets the idle timer on user activity", () => {
        const onLock = vi.fn();
        renderHook(() => useIdleLock({ minutes: 1, lockOnBlur: false, onLock }));
        vi.advanceTimersByTime(40_000);
        window.dispatchEvent(new Event("mousemove"));
        // 40s since the reset — still under the 60s timeout.
        vi.advanceTimersByTime(40_000);
        expect(onLock).not.toHaveBeenCalled();
        // Crossing 60s since the reset triggers the lock.
        vi.advanceTimersByTime(25_000);
        expect(onLock).toHaveBeenCalledTimes(1);
    });

    it("never starts the idle timer when minutes is 0", () => {
        const onLock = vi.fn();
        renderHook(() => useIdleLock({ minutes: 0, lockOnBlur: false, onLock }));
        vi.advanceTimersByTime(10 * 60_000);
        expect(onLock).not.toHaveBeenCalled();
    });

    it("locks shortly after blur when lockOnBlur is on", () => {
        const onLock = vi.fn();
        renderHook(() => useIdleLock({ minutes: 0, lockOnBlur: true, onLock }));
        window.dispatchEvent(new Event("blur"));
        // Grace period — not yet.
        expect(onLock).not.toHaveBeenCalled();
        vi.advanceTimersByTime(1_500);
        expect(onLock).toHaveBeenCalledTimes(1);
    });

    it("cancels the blur lock when focus returns within the grace period", () => {
        const onLock = vi.fn();
        renderHook(() => useIdleLock({ minutes: 0, lockOnBlur: true, onLock }));
        window.dispatchEvent(new Event("blur"));
        vi.advanceTimersByTime(1_000);
        window.dispatchEvent(new Event("focus"));
        vi.advanceTimersByTime(1_000);
        expect(onLock).not.toHaveBeenCalled();
    });
});
