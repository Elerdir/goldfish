import { useEffect } from "react";
import { Settings as SettingsIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { isTauri, openSettingsWindow } from "@/lib/tauri";
import { updates, useUpdates } from "@/lib/updates";

// TopBar remounts with screen changes; check UpdateHub once per app start.
let startupCheckScheduled = false;

export function TopBar() {
    const { t } = useTranslation();
    const { status } = useUpdates();
    const updateAvailable = status === "available";

    // Silent update check shortly after start (not in dev - there is no release to compare with).
    useEffect(() => {
        if (startupCheckScheduled || !isTauri() || import.meta.env.DEV) return;
        startupCheckScheduled = true;
        setTimeout(() => void updates.check(true), 3000);
    }, []);

    return (
        <header className="flex items-center justify-between border-b border-border px-5 py-3">
            <div className="flex items-center gap-2">
                <span className="text-lg" aria-hidden>
                    🐠
                </span>
                <span className="font-semibold tracking-tight">{t("app.name")}</span>
            </div>

            <Button
                variant="ghost"
                onClick={() => void openSettingsWindow()}
                aria-label={updateAvailable ? t("updates.badge") : t("settings.title")}
                title={updateAvailable ? t("updates.badge") : t("settings.title")}
                className="relative px-2"
            >
                <SettingsIcon size={18} />
                {updateAvailable && (
                    <span
                        className="absolute right-1 top-1 h-2 w-2 rounded-full bg-primary"
                        aria-hidden
                    />
                )}
            </Button>
        </header>
    );
}
