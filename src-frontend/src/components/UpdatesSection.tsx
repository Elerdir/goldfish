import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { isTauri } from "@/lib/tauri";
import { updates, useUpdates } from "@/lib/updates";

/** Settings → Updates: check UpdateHub, install the update, restart. */
export function UpdatesSection({ version }: { version: string | null }) {
    const { t } = useTranslation();
    const state = useUpdates();

    // The settings window has its own store: check once when it opens.
    useEffect(() => {
        if (isTauri() && !import.meta.env.DEV) void updates.check(true);
    }, []);

    return (
        <section className="flex flex-col gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t("updates.title")}
            </h3>

            <p className="text-sm">
                {version ? t("updates.current", { version }) : t("updates.current_unknown")}
            </p>

            {state.status === "checking" && (
                <p className="text-xs text-muted-foreground">{t("updates.checking")}</p>
            )}
            {state.status === "up_to_date" && (
                <p className="text-xs text-muted-foreground">{t("updates.up_to_date")}</p>
            )}
            {(state.status === "available" || state.status === "downloading" || state.status === "ready") && (
                <div className="flex flex-col gap-1.5 rounded-md border border-border p-3">
                    <p className="text-sm font-medium">
                        {t("updates.available", { version: state.version })}
                    </p>
                    {state.notes && (
                        <p className="whitespace-pre-line text-xs text-muted-foreground">{state.notes}</p>
                    )}
                </div>
            )}
            {state.status === "downloading" && (
                <p className="text-xs text-muted-foreground">
                    {state.progress === null
                        ? t("updates.downloading")
                        : t("updates.downloading_progress", { progress: state.progress })}
                </p>
            )}
            {state.status === "ready" && (
                <p className="text-xs text-green-600 dark:text-green-400">{t("updates.ready")}</p>
            )}
            {state.status === "error" && (
                <p className="text-xs text-destructive">{t("updates.error", { message: state.error })}</p>
            )}

            <div className="flex flex-wrap gap-2">
                {state.status === "available" ? (
                    <Button onClick={() => void updates.install()}>{t("updates.install")}</Button>
                ) : state.status === "ready" ? (
                    <Button onClick={() => void updates.relaunch()}>{t("updates.restart")}</Button>
                ) : (
                    <Button
                        variant="outline"
                        disabled={!isTauri() || state.status === "checking" || state.status === "downloading"}
                        onClick={() => void updates.check()}
                    >
                        {t("updates.check")}
                    </Button>
                )}
            </div>
        </section>
    );
}
