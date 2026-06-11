import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it } from "vitest";

import { ThemeProvider, useTheme } from "./ThemeProvider";

function wrapper({ children }: { children: ReactNode }) {
    return <ThemeProvider>{children}</ThemeProvider>;
}

describe("ThemeProvider", () => {
    beforeEach(() => {
        window.localStorage.clear();
        document.documentElement.className = "";
    });

    it("defaults to system and resolves to light (matchMedia stubbed)", () => {
        const { result } = renderHook(() => useTheme(), { wrapper });
        expect(result.current.theme).toBe("system");
        expect(result.current.resolvedTheme).toBe("light");
        expect(document.documentElement.classList.contains("light")).toBe(true);
    });

    it("applies the dark class and persists when set to dark", () => {
        const { result } = renderHook(() => useTheme(), { wrapper });
        act(() => result.current.setTheme("dark"));
        expect(result.current.resolvedTheme).toBe("dark");
        expect(document.documentElement.classList.contains("dark")).toBe(true);
        expect(document.documentElement.classList.contains("light")).toBe(false);
        expect(window.localStorage.getItem("goldfish-theme")).toBe("dark");
    });

    it("restores a persisted theme on mount", () => {
        window.localStorage.setItem("goldfish-theme", "dark");
        const { result } = renderHook(() => useTheme(), { wrapper });
        expect(result.current.theme).toBe("dark");
        expect(document.documentElement.classList.contains("dark")).toBe(true);
    });
});
