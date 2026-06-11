import { Settings as SettingsIcon } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { openSettingsWindow } from "@/lib/tauri";

export function TopBar() {
    const { t } = useTranslation();

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
                aria-label={t("settings.title")}
                title={t("settings.title")}
                className="px-2"
            >
                <SettingsIcon size={18} />
            </Button>
        </header>
    );
}
