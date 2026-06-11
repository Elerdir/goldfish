import { useCallback, useEffect, useState } from "react";
import { FolderOpen, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { openLogsDir, readLogs } from "@/lib/tauri";

/**
 * Read-only viewer for the rolling log file — lets the user see what happened
 * (errors, events) to diagnose crashes. Logs never contain secrets.
 */
export function LogViewer({ open, onClose }: { open: boolean; onClose: () => void }) {
    const { t } = useTranslation();
    const [text, setText] = useState("");
    const [loading, setLoading] = useState(false);

    const refresh = useCallback(() => {
        setLoading(true);
        void readLogs()
            .then(setText)
            .catch(() => setText(""))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        if (open) refresh();
    }, [open, refresh]);

    return (
        <Dialog
            open={open}
            onClose={onClose}
            title={t("logs.title")}
            footer={
                <>
                    <Button variant="ghost" onClick={() => void openLogsDir()}>
                        <FolderOpen size={16} />
                        {t("logs.open_folder")}
                    </Button>
                    <Button variant="outline" onClick={refresh}>
                        <RefreshCw size={16} />
                        {t("logs.refresh")}
                    </Button>
                    <Button onClick={onClose}>{t("settings.close")}</Button>
                </>
            }
        >
            {loading && text === "" ? (
                <p className="text-sm text-muted-foreground">{t("logs.loading")}</p>
            ) : text.trim() === "" ? (
                <p className="text-sm text-muted-foreground">{t("logs.empty")}</p>
            ) : (
                <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">
                    {text}
                </pre>
            )}
        </Dialog>
    );
}
