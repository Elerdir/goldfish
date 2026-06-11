import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Pretend we're running inside Tauri and stub the IPC surface the provider uses.
vi.mock("@/lib/tauri", () => ({
    isTauri: () => true,
    asCommandError: (e: unknown) =>
        typeof e === "object" && e !== null && "kind" in e
            ? (e as { kind: string; message: string })
            : { kind: "unknown", message: "" },
    vaultExists: vi.fn(),
    isUnlocked: vi.fn(),
    biometricEnabled: vi.fn().mockResolvedValue(false),
    createVault: vi.fn(),
    unlockVault: vi.fn(),
    unlockBiometric: vi.fn(),
    unlockWithRecovery: vi.fn(),
    lockVault: vi.fn(),
}));

// The provider resizes the main window on status changes; stub the window API.
vi.mock("@tauri-apps/api/window", () => ({
    getCurrentWindow: () => ({
        label: "main",
        setSize: vi.fn().mockResolvedValue(undefined),
        center: vi.fn().mockResolvedValue(undefined),
    }),
    LogicalSize: class {
        constructor(
            public width: number,
            public height: number,
        ) {}
    },
}));

import {
    biometricEnabled,
    isUnlocked,
    unlockVault,
    vaultExists,
} from "@/lib/tauri";

import { VaultProvider, useVault } from "./VaultProvider";

function wrapper({ children }: { children: ReactNode }) {
    return <VaultProvider>{children}</VaultProvider>;
}

describe("VaultProvider", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(biometricEnabled).mockResolvedValue(false);
    });

    it("shows onboarding when no vault exists", async () => {
        vi.mocked(vaultExists).mockResolvedValue(false);
        vi.mocked(isUnlocked).mockResolvedValue(false);
        const { result } = renderHook(() => useVault(), { wrapper });
        await waitFor(() => expect(result.current.status).toBe("onboarding"));
    });

    it("shows locked when a vault exists and the backend is not unlocked", async () => {
        vi.mocked(vaultExists).mockResolvedValue(true);
        vi.mocked(isUnlocked).mockResolvedValue(false);
        const { result } = renderHook(() => useVault(), { wrapper });
        await waitFor(() => expect(result.current.status).toBe("locked"));
    });

    it("reflects an already-unlocked backend on init (sub-window / reload)", async () => {
        vi.mocked(vaultExists).mockResolvedValue(true);
        vi.mocked(isUnlocked).mockResolvedValue(true);
        const { result } = renderHook(() => useVault(), { wrapper });
        await waitFor(() => expect(result.current.status).toBe("unlocked"));
    });

    it("transitions to unlocked after a successful unlock()", async () => {
        vi.mocked(vaultExists).mockResolvedValue(true);
        vi.mocked(isUnlocked).mockResolvedValue(false);
        vi.mocked(unlockVault).mockResolvedValue(undefined);
        const { result } = renderHook(() => useVault(), { wrapper });
        await waitFor(() => expect(result.current.status).toBe("locked"));
        await act(async () => {
            await result.current.unlock("master");
        });
        expect(result.current.status).toBe("unlocked");
    });

    it("surfaces a localized error key when unlock fails", async () => {
        vi.mocked(vaultExists).mockResolvedValue(true);
        vi.mocked(isUnlocked).mockResolvedValue(false);
        vi.mocked(unlockVault).mockRejectedValue({ kind: "invalid_password", message: "" });
        const { result } = renderHook(() => useVault(), { wrapper });
        await waitFor(() => expect(result.current.status).toBe("locked"));
        await act(async () => {
            await result.current.unlock("wrong");
        });
        expect(result.current.status).toBe("locked");
        expect(result.current.errorKey).toBe("errors.invalid_password");
    });
});
