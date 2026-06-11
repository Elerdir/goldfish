import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";

import {
    asCommandError,
    biometricEnabled as ipcBiometricEnabled,
    createVault as ipcCreate,
    isTauri,
    isUnlocked as ipcIsUnlocked,
    lockVault as ipcLock,
    unlockBiometric as ipcUnlockBiometric,
    unlockVault as ipcUnlock,
    unlockWithRecovery as ipcUnlockWithRecovery,
    vaultExists,
} from "@/lib/tauri";

/** Vault lifecycle status driving which screen is shown. */
export type VaultStatus = "loading" | "onboarding" | "locked" | "unlocked";

interface VaultContextValue {
    status: VaultStatus;
    /** Localization key for the current error, or null. */
    errorKey: string | null;
    /** False when running in a plain browser (no Tauri backend). */
    backendAvailable: boolean;
    busy: boolean;
    /** Whether biometric unlock is enabled for the vault. */
    biometricEnabled: boolean;
    createVault: (password: string) => Promise<void>;
    unlock: (password: string) => Promise<void>;
    unlockBiometric: () => Promise<void>;
    /** Unlocks via a recovery code, resetting the master password. */
    unlockWithRecovery: (code: string, newPassword: string) => Promise<void>;
    lock: () => Promise<void>;
    /** Re-reads whether biometric unlock is enabled (after toggling in settings). */
    refreshBiometric: () => Promise<void>;
    /** Dev-only: force a screen when no backend is present (browser preview). */
    setPreviewStatus: (status: VaultStatus) => void;
}

const VaultContext = createContext<VaultContextValue | null>(null);

function errorKeyFor(kind: string): string {
    switch (kind) {
        case "invalid_password":
            return "errors.invalid_password";
        case "vault_exists":
            return "errors.vault_exists";
        case "vault_not_found":
            return "errors.vault_not_found";
        case "biometric_unavailable":
            return "errors.biometric_unavailable";
        case "biometric_not_enabled":
            return "errors.biometric_not_enabled";
        case "biometric_failed":
            return "errors.biometric_failed";
        case "invalid_recovery_code":
            return "errors.invalid_recovery_code";
        case "recovery_not_enabled":
            return "errors.recovery_not_enabled";
        case "throttled":
            return "errors.throttled";
        default:
            return "errors.generic";
    }
}

export function VaultProvider({ children }: { children: ReactNode }) {
    const [status, setStatus] = useState<VaultStatus>("loading");
    const [errorKey, setErrorKey] = useState<string | null>(null);
    const [backendAvailable, setBackendAvailable] = useState(true);
    const [busy, setBusy] = useState(false);
    const [biometricEnabled, setBiometricEnabled] = useState(false);

    const refreshBiometric = useCallback(async () => {
        if (!isTauri()) {
            setBiometricEnabled(false);
            return;
        }
        try {
            setBiometricEnabled(await ipcBiometricEnabled());
        } catch {
            setBiometricEnabled(false);
        }
    }, []);

    useEffect(() => {
        let cancelled = false;
        async function init() {
            if (!isTauri()) {
                if (!cancelled) {
                    setBackendAvailable(false);
                    setStatus("onboarding");
                }
                return;
            }
            try {
                const exists = await vaultExists();
                await refreshBiometric();
                if (cancelled) return;
                if (!exists) {
                    setStatus("onboarding");
                    return;
                }
                // A sibling window (Settings/Entry) or a dev reload may share an
                // already-unlocked backend session. Reflect the real backend state
                // so those windows enable unlocked-only controls (biometrics,
                // import, backup) instead of assuming "locked".
                const unlocked = await ipcIsUnlocked();
                if (!cancelled) setStatus(unlocked ? "unlocked" : "locked");
            } catch (err) {
                if (!cancelled) {
                    setErrorKey(errorKeyFor(asCommandError(err).kind));
                    setStatus("onboarding");
                }
            }
        }
        void init();
        return () => {
            cancelled = true;
        };
    }, [refreshBiometric]);

    // Fit the window to the screen: compact for the auth/onboarding screens,
    // roomy once the vault is unlocked (folder rail + entry list need space).
    useEffect(() => {
        if (!isTauri() || status === "loading") return;
        const win = getCurrentWindow();
        // Only the main window auto-sizes; sub-windows (settings, entry, logs)
        // manage their own dimensions.
        if (win.label !== "main") return;
        const compact = status !== "unlocked";
        void (async () => {
            try {
                await win.setSize(compact ? new LogicalSize(520, 680) : new LogicalSize(1100, 840));
                await win.center();
            } catch {
                /* window controls unavailable (e.g. browser preview) — ignore */
            }
        })();
    }, [status]);

    const createVault = useCallback(async (password: string) => {
        setBusy(true);
        setErrorKey(null);
        try {
            await ipcCreate(password);
            setStatus("unlocked");
        } catch (err) {
            setErrorKey(errorKeyFor(asCommandError(err).kind));
        } finally {
            setBusy(false);
        }
    }, []);

    const unlock = useCallback(async (password: string) => {
        setBusy(true);
        setErrorKey(null);
        try {
            await ipcUnlock(password);
            setStatus("unlocked");
        } catch (err) {
            setErrorKey(errorKeyFor(asCommandError(err).kind));
        } finally {
            setBusy(false);
        }
    }, []);

    const unlockBiometric = useCallback(async () => {
        setBusy(true);
        setErrorKey(null);
        try {
            await ipcUnlockBiometric();
            setStatus("unlocked");
        } catch (err) {
            setErrorKey(errorKeyFor(asCommandError(err).kind));
        } finally {
            setBusy(false);
        }
    }, []);

    const unlockWithRecovery = useCallback(async (code: string, newPassword: string) => {
        setBusy(true);
        setErrorKey(null);
        try {
            await ipcUnlockWithRecovery(code, newPassword);
            setStatus("unlocked");
        } catch (err) {
            setErrorKey(errorKeyFor(asCommandError(err).kind));
        } finally {
            setBusy(false);
        }
    }, []);

    const lock = useCallback(async () => {
        setBusy(true);
        try {
            await ipcLock();
        } catch {
            // Even if the backend errors, present a locked UI.
        } finally {
            await refreshBiometric();
            setStatus("locked");
            setErrorKey(null);
            setBusy(false);
        }
    }, [refreshBiometric]);

    const setPreviewStatus = useCallback((next: VaultStatus) => {
        setErrorKey(null);
        setStatus(next);
    }, []);

    const value = useMemo<VaultContextValue>(
        () => ({
            status,
            errorKey,
            backendAvailable,
            busy,
            biometricEnabled,
            createVault,
            unlock,
            unlockBiometric,
            unlockWithRecovery,
            lock,
            refreshBiometric,
            setPreviewStatus,
        }),
        [
            status,
            errorKey,
            backendAvailable,
            busy,
            biometricEnabled,
            createVault,
            unlock,
            unlockBiometric,
            unlockWithRecovery,
            lock,
            refreshBiometric,
            setPreviewStatus,
        ],
    );

    return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useVault(): VaultContextValue {
    const ctx = useContext(VaultContext);
    if (!ctx) throw new Error("useVault must be used inside <VaultProvider>");
    return ctx;
}
