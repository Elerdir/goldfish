import { createFileRoute } from "@tanstack/react-router";
import { Loader2 } from "lucide-react";
import { useTranslation } from "react-i18next";

import { TopBar } from "@/components/TopBar";
import { OnboardingScreen } from "@/screens/OnboardingScreen";
import { UnlockScreen } from "@/screens/UnlockScreen";
import { VaultView } from "@/screens/VaultView";
import { useVault, type VaultStatus } from "@/providers/VaultProvider";

export const Route = createFileRoute("/")({
    component: VaultGate,
});

const PREVIEW_STATES: VaultStatus[] = ["onboarding", "locked", "unlocked"];

function DevPreviewBar() {
    const { status, setPreviewStatus } = useVault();
    return (
        <div className="flex items-center gap-2 border-b border-amber-500/40 bg-amber-500/10 px-5 py-2 text-xs text-amber-700 dark:text-amber-300">
            <span className="font-medium">dev preview (no backend):</span>
            {PREVIEW_STATES.map((s) => (
                <button
                    key={s}
                    type="button"
                    onClick={() => setPreviewStatus(s)}
                    className={`rounded px-2 py-0.5 ${
                        status === s ? "bg-amber-500 text-white" : "hover:bg-amber-500/20"
                    }`}
                >
                    {s}
                </button>
            ))}
        </div>
    );
}

function VaultGate() {
    const { t } = useTranslation();
    const { status, backendAvailable } = useVault();

    // The unlocked vault view manages its own full-height layout.
    if (status === "unlocked") {
        return (
            <div className="flex h-full flex-col">
                <TopBar />
                {!backendAvailable && <DevPreviewBar />}
                <main className="min-h-0 flex-1">
                    <VaultView />
                </main>
            </div>
        );
    }

    return (
        <div className="flex min-h-full flex-col">
            <TopBar />
            {!backendAvailable && <DevPreviewBar />}
            <main className="flex flex-1 items-center justify-center p-6">
                {status === "loading" && (
                    <Loader2 className="animate-spin text-muted-foreground" size={28} />
                )}
                {status === "onboarding" && <OnboardingScreen />}
                {status === "locked" && <UnlockScreen />}
            </main>
            <footer className="px-5 py-3 text-center text-xs text-muted-foreground">
                {t("app.tagline")}
            </footer>
        </div>
    );
}
