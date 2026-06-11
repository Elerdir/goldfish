import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { EMPTY_APPEARANCE, type Appearance } from "@/lib/tauri";

/** User-configurable behavior settings (no secrets — persisted to localStorage). */
export interface Settings {
    /** Minutes of inactivity before the vault auto-locks. 0 disables idle lock. */
    autoLockMinutes: number;
    /** Lock the vault when the window loses focus. */
    lockOnBlur: boolean;
    /** Seconds before a copied secret is cleared from the clipboard. */
    clipboardClearSeconds: number;
    /** Appearance overrides for the "all entries" view (folders store their own). */
    allEntriesAppearance: Appearance;
    /** Remind to change a password older than this many days. 0 disables it. */
    passwordExpiryDays: number;
}

const STORAGE_KEY = "goldfish-settings";

const DEFAULTS: Settings = {
    autoLockMinutes: 5,
    lockOnBlur: false,
    clipboardClearSeconds: 20,
    allEntriesAppearance: EMPTY_APPEARANCE,
    // Off by default — modern guidance (NIST) discourages forced rotation; this
    // is an opt-in reminder for users who still want one.
    passwordExpiryDays: 0,
};

const MIN_FONT = 10;
const MAX_FONT = 28;
const HEX_COLOR = /^#(?:[0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

function clamp(value: number, min: number, max: number): number {
    return Math.min(Math.max(value, min), max);
}

/** Mirrors the Rust validation: hex-only colors, clamped font, defaults elsewhere. */
function sanitizeAppearance(raw: unknown): Appearance {
    if (typeof raw !== "object" || raw === null) return EMPTY_APPEARANCE;
    const r = raw as Record<string, unknown>;
    const color = (v: unknown) =>
        typeof v === "string" && HEX_COLOR.test(v) ? v.toLowerCase() : null;
    return {
        background: color(r.background),
        textColor: color(r.textColor),
        bold: r.bold === true,
        italic: r.italic === true,
        fontSize: typeof r.fontSize === "number" ? clamp(Math.round(r.fontSize), MIN_FONT, MAX_FONT) : null,
    };
}

function sanitize(raw: unknown): Settings {
    if (typeof raw !== "object" || raw === null) return DEFAULTS;
    const r = raw as Record<string, unknown>;
    return {
        autoLockMinutes:
            typeof r.autoLockMinutes === "number" ? clamp(r.autoLockMinutes, 0, 240) : DEFAULTS.autoLockMinutes,
        lockOnBlur: typeof r.lockOnBlur === "boolean" ? r.lockOnBlur : DEFAULTS.lockOnBlur,
        clipboardClearSeconds:
            typeof r.clipboardClearSeconds === "number"
                ? clamp(r.clipboardClearSeconds, 5, 300)
                : DEFAULTS.clipboardClearSeconds,
        allEntriesAppearance: sanitizeAppearance(r.allEntriesAppearance),
        passwordExpiryDays:
            typeof r.passwordExpiryDays === "number"
                ? clamp(Math.round(r.passwordExpiryDays), 0, 3650)
                : DEFAULTS.passwordExpiryDays,
    };
}

function load(): Settings {
    try {
        const raw = window.localStorage.getItem(STORAGE_KEY);
        if (raw) return sanitize(JSON.parse(raw));
    } catch {
        // ignore — fall back to defaults
    }
    return DEFAULTS;
}

interface SettingsContextValue {
    settings: Settings;
    update: (partial: Partial<Settings>) => void;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
    const [settings, setSettings] = useState<Settings>(load);

    // Live-sync across windows: the Settings window persists to localStorage,
    // which fires a `storage` event here in the main window.
    useEffect(() => {
        const onStorage = (e: StorageEvent) => {
            if (e.key === STORAGE_KEY) setSettings(load());
        };
        window.addEventListener("storage", onStorage);
        return () => window.removeEventListener("storage", onStorage);
    }, []);

    const update = useCallback((partial: Partial<Settings>) => {
        setSettings((prev) => {
            const next = sanitize({ ...prev, ...partial });
            try {
                window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
            } catch {
                // ignore persistence failure
            }
            return next;
        });
    }, []);

    const value = useMemo<SettingsContextValue>(() => ({ settings, update }), [settings, update]);

    return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSettings(): SettingsContextValue {
    const ctx = useContext(SettingsContext);
    if (!ctx) throw new Error("useSettings must be used inside <SettingsProvider>");
    return ctx;
}
