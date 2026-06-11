import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { FolderOpen, RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useExcludeFromCapture } from "@/hooks/useExcludeFromCapture";
import { openLogsDir, readLogs } from "@/lib/tauri";
import { cn } from "@/lib/utils";

/** Log severity levels we color-code (others render neutral). */
type Level = "error" | "warn" | "info" | "debug" | "trace";

const LEVELS: Level[] = ["error", "warn", "info", "debug", "trace"];

const LEVEL_STYLE: Record<Level, string> = {
    error: "text-red-600 dark:text-red-400",
    warn: "text-amber-600 dark:text-amber-400",
    info: "text-sky-700 dark:text-sky-300",
    debug: "text-muted-foreground",
    trace: "text-muted-foreground",
};

/** Detects the tracing level token in a log line (`… INFO goldfish: …`). */
function levelOf(line: string): Level | null {
    const m = /\b(ERROR|WARN|INFO|DEBUG|TRACE)\b/.exec(line);
    const token = m?.[1];
    return token ? (token.toLowerCase() as Level) : null;
}

/** Auto-refresh interval while polling is enabled. */
const POLL_MS = 2000;

/**
 * Standalone log-viewer window (opened with `?view=logs`). Shows the rolling log
 * file's tail with color-coded levels, a level filter, search, auto-scroll and
 * optional live auto-refresh. Logs never contain secrets.
 */
export function LogWindow() {
    useExcludeFromCapture();
    const { t } = useTranslation();
    const [text, setText] = useState("");
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [hidden, setHidden] = useState<Set<Level>>(new Set());
    const [autoScroll, setAutoScroll] = useState(true);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const scrollRef = useRef<HTMLDivElement>(null);

    const refresh = useCallback(() => {
        void readLogs()
            .then(setText)
            .catch(() => setText(""))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    // Live tail: poll while auto-refresh is on.
    useEffect(() => {
        if (!autoRefresh) return;
        const id = window.setInterval(refresh, POLL_MS);
        return () => window.clearInterval(id);
    }, [autoRefresh, refresh]);

    const lines = useMemo(() => {
        const q = search.trim().toLowerCase();
        return text
            .split("\n")
            .map((raw, i) => ({ raw, level: levelOf(raw), key: i }))
            .filter(({ raw, level }) => {
                if (level && hidden.has(level)) return false;
                if (q && !raw.toLowerCase().includes(q)) return false;
                return raw.trim() !== "";
            });
    }, [text, search, hidden]);

    // Keep the newest lines in view as they stream in.
    useEffect(() => {
        if (autoScroll && scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [lines, autoScroll]);

    const toggleLevel = (level: Level) =>
        setHidden((prev) => {
            const next = new Set(prev);
            if (next.has(level)) next.delete(level);
            else next.add(level);
            return next;
        });

    return (
        <div className="flex h-screen flex-col bg-background text-foreground">
            <header className="flex items-center gap-2 border-b border-border px-4 py-2.5">
                <h1 className="text-sm font-semibold">{t("logs.title")}</h1>
                <div className="ml-auto flex items-center gap-2">
                    <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <input
                            type="checkbox"
                            checked={autoRefresh}
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                            className="h-3.5 w-3.5 accent-primary"
                        />
                        {t("logs.autorefresh")}
                    </label>
                    <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <input
                            type="checkbox"
                            checked={autoScroll}
                            onChange={(e) => setAutoScroll(e.target.checked)}
                            className="h-3.5 w-3.5 accent-primary"
                        />
                        {t("logs.autoscroll")}
                    </label>
                    <Button variant="outline" className="h-8 px-2.5" onClick={refresh}>
                        <RefreshCw size={14} />
                        {t("logs.refresh")}
                    </Button>
                    <Button variant="ghost" className="h-8 px-2.5" onClick={() => void openLogsDir()}>
                        <FolderOpen size={14} />
                        {t("logs.open_folder")}
                    </Button>
                </div>
            </header>

            <div className="flex items-center gap-2 border-b border-border px-4 py-2">
                <Input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder={t("logs.search")}
                    className="h-8 max-w-xs"
                />
                <div className="flex gap-1">
                    {LEVELS.map((level) => {
                        const on = !hidden.has(level);
                        return (
                            <button
                                key={level}
                                type="button"
                                onClick={() => toggleLevel(level)}
                                className={cn(
                                    "rounded-md border px-2 py-1 text-[11px] font-medium uppercase transition-colors",
                                    on
                                        ? "border-border bg-accent text-accent-foreground"
                                        : "border-border text-muted-foreground/50 line-through",
                                )}
                            >
                                {level}
                            </button>
                        );
                    })}
                </div>
            </div>

            <div ref={scrollRef} className="min-h-0 flex-1 overflow-auto bg-muted/30 p-3">
                {loading && text === "" ? (
                    <p className="text-sm text-muted-foreground">{t("logs.loading")}</p>
                ) : lines.length === 0 ? (
                    <p className="text-sm text-muted-foreground">{t("logs.empty")}</p>
                ) : (
                    <div className="font-mono text-xs leading-relaxed">
                        {lines.map(({ raw, level, key }) => (
                            <div
                                key={key}
                                className={cn(
                                    "whitespace-pre-wrap break-all",
                                    level ? LEVEL_STYLE[level] : "text-foreground",
                                )}
                            >
                                {raw}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
