import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listen } from "@tauri-apps/api/event";
import {
    CreditCard,
    KeyRound,
    KeySquare,
    Lock,
    Palette,
    Plus,
    Search,
    ShieldCheck,
    Star,
    StickyNote,
    TerminalSquare,
    X,
    type LucideIcon,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { AppearanceDialog } from "@/components/AppearanceDialog";
import { EntryDetailDialog } from "@/components/EntryDetailDialog";
import { FolderSidebar } from "@/components/FolderSidebar";
import { HealthDialog } from "@/components/HealthDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useIdleLock } from "@/hooks/useIdleLock";
import { appearanceTextStyle } from "@/lib/appearance";
import { ENTRY_MIME } from "@/lib/dnd";
import {
    deleteEntry,
    deleteTag,
    isTauri,
    listEntries,
    listFolders,
    listTags,
    openEntryWindow,
    reorderEntries,
    setFolderAppearance,
    EMPTY_APPEARANCE,
    VAULT_CHANGED_EVENT,
    type Appearance,
    type EntryKind,
    type EntrySummary,
} from "@/lib/tauri";
import { cn } from "@/lib/utils";
import { useSettings } from "@/providers/SettingsProvider";
import { useVault } from "@/providers/VaultProvider";

export function VaultView() {
    const { t } = useTranslation();
    const { lock } = useVault();
    const { settings, update } = useSettings();
    const qc = useQueryClient();

    // Auto-lock on inactivity / window blur while the vault is open.
    const onIdleLock = useCallback(() => void lock(), [lock]);
    useIdleLock({
        minutes: settings.autoLockMinutes,
        lockOnBlur: settings.lockOnBlur,
        onLock: onIdleLock,
    });

    const [search, setSearch] = useState("");
    const [folderId, setFolderId] = useState<string | null>(null);
    const [tagFilter, setTagFilter] = useState<string | null>(null);
    const [detailId, setDetailId] = useState<string | null>(null);
    const [healthOpen, setHealthOpen] = useState(false);
    const [appearanceOpen, setAppearanceOpen] = useState(false);
    const [toast, setToast] = useState<string | null>(null);
    // `dropTarget` is the row currently under the dragged item, plus whether the
    // drop would land after it (pointer past its vertical midpoint).
    const [dragId, setDragId] = useState<string | null>(null);
    const [dropTarget, setDropTarget] = useState<{ id: string; after: boolean } | null>(null);

    const entriesQuery = useQuery({
        queryKey: ["entries", folderId],
        queryFn: () => listEntries(folderId),
    });
    // Shares the cache key with FolderSidebar — used here to read the selected
    // folder's appearance overrides.
    const foldersQuery = useQuery({ queryKey: ["folders"], queryFn: listFolders });
    const tagsQuery = useQuery({ queryKey: ["tags"], queryFn: listTags });
    // Tag id → name, for rendering chips on rows and the detail view.
    const tagNames = useMemo(
        () => new Map((tagsQuery.data ?? []).map((tag) => [tag.id, tag.name])),
        [tagsQuery.data],
    );

    // Active view's appearance: the "all entries" view comes from settings, a
    // folder view from the folder record. Drives the list panel + entry text.
    const appearance: Appearance =
        folderId === null
            ? settings.allEntriesAppearance
            : (foldersQuery.data?.find((f) => f.id === folderId)?.appearance ?? EMPTY_APPEARANCE);
    const textStyle = appearanceTextStyle(appearance);

    /** Persists the edited appearance to the right place for the current view. */
    const saveAppearance = (next: Appearance) => {
        setAppearanceOpen(false);
        if (folderId === null) {
            update({ allEntriesAppearance: next });
        } else {
            void setFolderAppearance(folderId, next).then(() =>
                qc.invalidateQueries({ queryKey: ["folders"] }),
            );
        }
    };

    // Manual reordering is only meaningful over the full list, so it is disabled
    // while a search or tag filter narrows it.
    const searching = search.trim() !== "" || tagFilter !== null;

    /** Moves the dragged entry next to the target row and persists the new order. */
    const reorderTo = (targetId: string, after: boolean) => {
        const all = entriesQuery.data ?? [];
        if (!dragId || searching || dragId === targetId) return;
        const without = all.map((e) => e.id).filter((id) => id !== dragId);
        const at = without.indexOf(targetId);
        if (at < 0) return;
        without.splice(after ? at + 1 : at, 0, dragId);
        const byId = new Map(all.map((e) => [e.id, e]));
        const reordered = without.map((id) => byId.get(id)).filter((e): e is EntrySummary => !!e);
        // Optimistically reflect the new order, then persist; on failure refetch.
        qc.setQueryData(["entries", folderId], reordered);
        void reorderEntries(folderId, without).catch(() =>
            qc.invalidateQueries({ queryKey: ["entries", folderId] }),
        );
    };

    const deleteMutation = useMutation({
        mutationFn: (id: string) => deleteEntry(id),
        onSuccess: () => {
            void qc.invalidateQueries({ queryKey: ["entries"] });
            setDetailId(null);
            showToast(t("entry.deleted"));
        },
    });

    const showToast = (msg: string) => setToast(msg);
    useEffect(() => {
        if (!toast) return;
        const id = window.setTimeout(() => setToast(null), 2500);
        return () => window.clearTimeout(id);
    }, [toast]);

    // The standalone entry/settings windows emit this when they change vault data.
    useEffect(() => {
        if (!isTauri()) return undefined;
        const unlisten = listen(VAULT_CHANGED_EVENT, () => {
            void qc.invalidateQueries({ queryKey: ["entries"] });
            void qc.invalidateQueries({ queryKey: ["folders"] });
            void qc.invalidateQueries({ queryKey: ["tags"] });
        });
        return () => void unlisten.then((fn) => fn());
    }, [qc]);

    const filtered = useMemo(() => {
        const all = entriesQuery.data ?? [];
        const q = search.trim().toLowerCase();
        return all.filter((e) => {
            if (tagFilter && !e.tags.includes(tagFilter)) return false;
            if (!q) return true;
            return (
                e.title.toLowerCase().includes(q) ||
                (e.url ?? "").toLowerCase().includes(q) ||
                (e.appName ?? "").toLowerCase().includes(q)
            );
        });
    }, [entriesQuery.data, search, tagFilter]);

    return (
        <div className="flex h-full w-full gap-4 p-4">
            <FolderSidebar selected={folderId} onSelect={setFolderId} />
            <main
                className="flex min-w-0 flex-1 flex-col gap-4 overflow-y-auto rounded-xl border border-border bg-card p-5 shadow-sm transition-colors"
                style={{ background: appearance.background ?? undefined }}
            >
            <div className="flex items-center gap-2">
                <div className="relative flex-1">
                    <Search
                        size={16}
                        className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                    />
                    <Input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder={t("vault.search")}
                        className="pl-9"
                    />
                </div>
                <Button onClick={() => void openEntryWindow()}>
                    <Plus size={16} />
                    {t("vault.add")}
                </Button>
                <Button
                    variant="outline"
                    onClick={() => setHealthOpen(true)}
                    aria-label={t("health.button")}
                    title={t("health.button")}
                    className="px-3"
                >
                    <ShieldCheck size={16} />
                </Button>
                <Button
                    variant="outline"
                    onClick={() => setAppearanceOpen(true)}
                    aria-label={t("appearance.button")}
                    title={t("appearance.button")}
                    className="px-3"
                >
                    <Palette size={16} />
                </Button>
                <Button variant="outline" onClick={() => void lock()}>
                    <Lock size={16} />
                    {t("vault.lock")}
                </Button>
            </div>

            {(tagsQuery.data ?? []).length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                    {(tagsQuery.data ?? []).map((tag) => {
                        const on = tagFilter === tag.id;
                        return (
                            <span
                                key={tag.id}
                                className={cn(
                                    "group inline-flex items-center rounded-full border text-xs transition-colors",
                                    on
                                        ? "border-primary bg-primary text-primary-foreground"
                                        : "border-border text-muted-foreground hover:bg-accent",
                                )}
                            >
                                <button
                                    type="button"
                                    onClick={() => setTagFilter(on ? null : tag.id)}
                                    aria-pressed={on}
                                    className="py-0.5 pl-2.5 pr-1"
                                >
                                    {tag.name}
                                </button>
                                <button
                                    type="button"
                                    onClick={() => {
                                        deleteTag(tag.id)
                                            .then(() => {
                                                if (tagFilter === tag.id) setTagFilter(null);
                                                return qc.invalidateQueries({ queryKey: ["tags"] });
                                            })
                                            .then(() => qc.invalidateQueries({ queryKey: ["entries"] }))
                                            .catch(() => {});
                                    }}
                                    aria-label={t("tag.delete")}
                                    title={t("tag.delete")}
                                    className="rounded-full px-1 opacity-0 transition-opacity hover:text-destructive focus-visible:opacity-100 group-hover:opacity-100"
                                >
                                    <X size={11} />
                                </button>
                            </span>
                        );
                    })}
                </div>
            )}

            {entriesQuery.isLoading && (
                <p className="text-sm text-muted-foreground">{t("vault.loading")}</p>
            )}
            {entriesQuery.isError && (
                <p className="text-sm text-destructive">{t("vault.load_error")}</p>
            )}
            {entriesQuery.isSuccess && filtered.length === 0 && (
                <div className="flex flex-1 flex-col items-center justify-center gap-2 text-center">
                    <p className="text-sm font-medium">{t("vault.empty")}</p>
                    <p className="text-sm text-muted-foreground">{t("vault.empty_hint")}</p>
                </div>
            )}

            <ul className="flex flex-col gap-1.5">
                {filtered.map((entry) => (
                    <EntryRow
                        key={entry.id}
                        entry={entry}
                        textStyle={textStyle}
                        tagNames={tagNames}
                        onClick={() => setDetailId(entry.id)}
                        draggable={!searching}
                        dragging={dragId === entry.id}
                        dropBefore={dropTarget?.id === entry.id && !dropTarget.after}
                        dropAfter={dropTarget?.id === entry.id && dropTarget.after}
                        onDragStart={(e) => {
                            e.dataTransfer.setData(ENTRY_MIME, entry.id);
                            e.dataTransfer.effectAllowed = "move";
                            setDragId(entry.id);
                        }}
                        onDragOver={(e) => {
                            if (searching || !dragId || dragId === entry.id) return;
                            e.preventDefault();
                            e.dataTransfer.dropEffect = "move";
                            const rect = e.currentTarget.getBoundingClientRect();
                            const after = e.clientY > rect.top + rect.height / 2;
                            setDropTarget({ id: entry.id, after });
                        }}
                        onDrop={(e) => {
                            e.preventDefault();
                            const rect = e.currentTarget.getBoundingClientRect();
                            reorderTo(entry.id, e.clientY > rect.top + rect.height / 2);
                            setDragId(null);
                            setDropTarget(null);
                        }}
                        onDragEnd={() => {
                            setDragId(null);
                            setDropTarget(null);
                        }}
                    />
                ))}
            </ul>

            <EntryDetailDialog
                open={detailId !== null}
                entryId={detailId}
                onClose={() => setDetailId(null)}
                onEdit={() => {
                    void openEntryWindow(detailId);
                    setDetailId(null);
                }}
                onDelete={() => {
                    if (detailId) deleteMutation.mutate(detailId);
                }}
                onCopied={() =>
                    showToast(t("entry.copied", { seconds: settings.clipboardClearSeconds }))
                }
            />

            <HealthDialog
                open={healthOpen}
                onClose={() => setHealthOpen(false)}
                onSelect={(id) => {
                    setHealthOpen(false);
                    setDetailId(id);
                }}
            />

            <AppearanceDialog
                open={appearanceOpen}
                title={`${t("appearance.title")} — ${
                    folderId === null
                        ? t("folder.all")
                        : (foldersQuery.data?.find((f) => f.id === folderId)?.name ?? "")
                }`}
                value={appearance}
                onClose={() => setAppearanceOpen(false)}
                onSave={saveAppearance}
            />

            {toast && (
                <div className="fixed bottom-5 left-1/2 z-50 -translate-x-1/2 rounded-md bg-foreground px-4 py-2 text-sm text-background shadow-lg">
                    {toast}
                </div>
            )}
            </main>
        </div>
    );
}

const KIND_ICONS: Record<EntryKind, LucideIcon> = {
    login: KeyRound,
    note: StickyNote,
    card: CreditCard,
    ssh: TerminalSquare,
    token: KeySquare,
};

type DragProps = {
    draggable?: boolean;
    dragging?: boolean;
    dropBefore?: boolean;
    dropAfter?: boolean;
    onDragStart?: (e: React.DragEvent) => void;
    onDragOver?: (e: React.DragEvent) => void;
    onDrop?: (e: React.DragEvent) => void;
    onDragEnd?: (e: React.DragEvent) => void;
};

function EntryRow({
    entry,
    onClick,
    textStyle,
    tagNames,
    draggable,
    dragging,
    dropBefore,
    dropAfter,
    onDragStart,
    onDragOver,
    onDrop,
    onDragEnd,
}: {
    entry: EntrySummary;
    onClick: () => void;
    textStyle?: React.CSSProperties;
    tagNames?: Map<string, string>;
} & DragProps) {
    const subtitle = entry.url ?? entry.appName ?? "";
    const Icon = KIND_ICONS[entry.kind] ?? KeyRound;
    const chips = entry.tags.map((id) => tagNames?.get(id)).filter((n): n is string => !!n);
    return (
        <li
            className={cn(
                "rounded-lg border-y-2 border-transparent transition-[border-color,opacity]",
                dragging && "opacity-40",
                dropBefore && "border-t-primary",
                dropAfter && "border-b-primary",
            )}
        >
            {/* A <div role="button"> (not a real <button>) so native HTML5 drag
                actually starts — a <button> swallows the drag in Chromium/WebView2. */}
            <div
                role="button"
                tabIndex={0}
                draggable={draggable}
                onClick={onClick}
                onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onClick();
                    }
                }}
                onDragStart={onDragStart}
                onDragOver={onDragOver}
                onDrop={onDrop}
                onDragEnd={onDragEnd}
                className={cn(
                    "flex w-full items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 text-left transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                    draggable && "cursor-grab active:cursor-grabbing",
                )}
            >
                <Icon size={16} className="shrink-0 text-muted-foreground" />
                <div className="flex min-w-0 flex-1 flex-col" style={textStyle}>
                    <span className="flex items-center gap-1.5 truncate font-medium">
                        {entry.title}
                        {entry.favorite && (
                            <Star size={14} className="fill-goldfish text-goldfish" />
                        )}
                    </span>
                    {subtitle && <span className="truncate text-xs opacity-70">{subtitle}</span>}
                </div>
                {chips.length > 0 && (
                    <div className="flex shrink-0 flex-wrap justify-end gap-1">
                        {chips.slice(0, 3).map((name) => (
                            <span
                                key={name}
                                className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
                            >
                                {name}
                            </span>
                        ))}
                    </div>
                )}
            </div>
        </li>
    );
}
