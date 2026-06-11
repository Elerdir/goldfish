import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { SettingsProvider, useSettings } from "./SettingsProvider";

function wrapper({ children }: { children: ReactNode }) {
    return <SettingsProvider>{children}</SettingsProvider>;
}

describe("SettingsProvider", () => {
    beforeEach(() => window.localStorage.clear());
    afterEach(() => window.localStorage.clear());

    it("provides sane defaults", () => {
        const { result } = renderHook(() => useSettings(), { wrapper });
        expect(result.current.settings.autoLockMinutes).toBe(5);
        expect(result.current.settings.clipboardClearSeconds).toBe(20);
        expect(result.current.settings.passwordExpiryDays).toBe(0);
        expect(result.current.settings.lockOnBlur).toBe(false);
    });

    it("clamps out-of-range values and persists them", () => {
        const { result } = renderHook(() => useSettings(), { wrapper });
        act(() => result.current.update({ autoLockMinutes: 9999, clipboardClearSeconds: 1 }));
        expect(result.current.settings.autoLockMinutes).toBe(240); // clamped to max
        expect(result.current.settings.clipboardClearSeconds).toBe(5); // clamped to min

        const raw = window.localStorage.getItem("goldfish-settings");
        expect(raw).not.toBeNull();
        const persisted = JSON.parse(raw ?? "{}") as { autoLockMinutes: number };
        expect(persisted.autoLockMinutes).toBe(240);
    });

    it("loads and sanitizes persisted settings on mount", () => {
        window.localStorage.setItem(
            "goldfish-settings",
            JSON.stringify({ autoLockMinutes: -10, clipboardClearSeconds: 9999, lockOnBlur: true }),
        );
        const { result } = renderHook(() => useSettings(), { wrapper });
        expect(result.current.settings.autoLockMinutes).toBe(0); // clamped to min
        expect(result.current.settings.clipboardClearSeconds).toBe(300); // clamped to max
        expect(result.current.settings.lockOnBlur).toBe(true);
    });

    it("rejects non-hex appearance colors and clamps the font size", () => {
        const { result } = renderHook(() => useSettings(), { wrapper });
        act(() =>
            result.current.update({
                allEntriesAppearance: {
                    background: "red", // not hex → rejected
                    textColor: "#ABCDEF", // valid → lowercased
                    bold: true,
                    italic: false,
                    fontSize: 999, // clamped to max (28)
                },
            }),
        );
        const a = result.current.settings.allEntriesAppearance;
        expect(a.background).toBeNull();
        expect(a.textColor).toBe("#abcdef");
        expect(a.fontSize).toBe(28);
    });
});
