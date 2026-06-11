import { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";

import { isTauri } from "@/lib/tauri";

export type Theme = "light" | "dark" | "system";

interface ThemeContextValue {
    theme: Theme;
    resolvedTheme: "light" | "dark";
    setTheme: (theme: Theme) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

interface ThemeProviderProps {
    children: ReactNode;
    defaultTheme?: Theme;
    storageKey?: string;
}

function readStoredTheme(storageKey: string, fallback: Theme): Theme {
    try {
        const value = window.localStorage.getItem(storageKey);
        if (value === "light" || value === "dark" || value === "system") {
            return value;
        }
    } catch {
        // localStorage may be unavailable (private mode, sandbox)
    }
    return fallback;
}

function resolveSystemTheme(): "light" | "dark" {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function ThemeProvider({
    children,
    defaultTheme = "system",
    storageKey = "goldfish-theme",
}: ThemeProviderProps) {
    const [theme, setThemeState] = useState<Theme>(() => readStoredTheme(storageKey, defaultTheme));
    const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">(() =>
        theme === "system" ? resolveSystemTheme() : theme,
    );

    useEffect(() => {
        const root = document.documentElement;
        const effective = theme === "system" ? resolveSystemTheme() : theme;
        root.classList.remove("light", "dark");
        root.classList.add(effective);
        setResolvedTheme(effective);
    }, [theme]);

    // Match the native window chrome (Windows/macOS title bar + min/close buttons)
    // to the resolved theme, for this window. Runs in every window, so each one's
    // title bar follows the app theme too.
    useEffect(() => {
        if (!isTauri()) return;
        void getCurrentWindow()
            .setTheme(resolvedTheme)
            .catch(() => {
                // setTheme may be unavailable (older webview / missing permission)
            });
    }, [resolvedTheme]);

    // Live-sync the theme across windows: changing it in the Settings window
    // writes localStorage, which fires a `storage` event in the main window.
    useEffect(() => {
        const onStorage = (e: StorageEvent) => {
            if (e.key === storageKey && (e.newValue === "light" || e.newValue === "dark" || e.newValue === "system")) {
                setThemeState(e.newValue);
            }
        };
        window.addEventListener("storage", onStorage);
        return () => window.removeEventListener("storage", onStorage);
    }, [storageKey]);

    useEffect(() => {
        if (theme !== "system") return;
        const media = window.matchMedia("(prefers-color-scheme: dark)");
        const onChange = () => {
            const effective = media.matches ? "dark" : "light";
            const root = document.documentElement;
            root.classList.remove("light", "dark");
            root.classList.add(effective);
            setResolvedTheme(effective);
        };
        media.addEventListener("change", onChange);
        return () => media.removeEventListener("change", onChange);
    }, [theme]);

    const value = useMemo<ThemeContextValue>(
        () => ({
            theme,
            resolvedTheme,
            setTheme: (next) => {
                try {
                    window.localStorage.setItem(storageKey, next);
                } catch {
                    // ignore — non-persistent fallback
                }
                setThemeState(next);
            },
        }),
        [theme, resolvedTheme, storageKey],
    );

    return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): ThemeContextValue {
    const ctx = useContext(ThemeContext);
    if (!ctx) {
        throw new Error("useTheme must be used inside <ThemeProvider>");
    }
    return ctx;
}
