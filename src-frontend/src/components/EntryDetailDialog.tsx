import { useCallback, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { open as openFileDialog, save as saveFileDialog } from "@tauri-apps/plugin-dialog";
import {
    Copy,
    Download,
    ExternalLink,
    Eye,
    EyeOff,
    Paperclip,
    Pencil,
    Plus,
    ShieldAlert,
    ShieldCheck,
    ShieldQuestion,
    Timer,
    Trash2,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { useSettings } from "@/providers/SettingsProvider";
import {
    addAttachment,
    addAttachmentBytes,
    asCommandError,
    checkPwned,
    copySecret,
    deleteAttachment,
    generateTotp,
    getEntry,
    listAttachments,
    listTags,
    MAX_ATTACHMENT_SIZE,
    openExternal,
    passwordHistory,
    saveAttachment,
    type AttachmentMeta,
    type CustomField,
    type PasswordHistoryItem,
} from "@/lib/tauri";

/** Breach-check outcome: not run, in progress, a count, or an error. */
type PwnedState = "idle" | "checking" | "error" | { count: number };

interface EntryDetailDialogProps {
    open: boolean;
    entryId: string | null;
    onClose: () => void;
    onEdit: () => void;
    onDelete: () => void;
    onCopied: () => void;
}

export function EntryDetailDialog({
    open,
    entryId,
    onClose,
    onEdit,
    onDelete,
    onCopied,
}: EntryDetailDialogProps) {
    const { t } = useTranslation();
    const { settings } = useSettings();
    const qc = useQueryClient();
    const [revealed, setRevealed] = useState(false);
    const [pwned, setPwned] = useState<PwnedState>("idle");

    // Secrets must not linger: don't cache the decrypted entry beyond its use.
    const query = useQuery({
        queryKey: ["entry", entryId],
        queryFn: () => getEntry(entryId as string),
        enabled: open && entryId !== null,
        gcTime: 0,
        staleTime: 0,
    });

    // Tag names for this entry's tag ids (cheap, cached briefly).
    const tagsQuery = useQuery({ queryKey: ["tags"], queryFn: listTags, enabled: open });

    // Reset the breach result whenever a different entry is opened.
    useEffect(() => {
        setPwned("idle");
        setRevealed(false);
    }, [entryId]);

    // Evict the decrypted entry from the query cache as soon as the dialog
    // closes, so the plaintext does not sit in renderer memory afterwards.
    useEffect(() => {
        if (!open && entryId !== null) {
            qc.removeQueries({ queryKey: ["entry", entryId] });
        }
    }, [open, entryId, qc]);

    const copy = (value: string) => {
        void copySecret(value, settings.clipboardClearSeconds * 1000).then(onCopied);
    };

    const runBreachCheck = (password: string) => {
        setPwned("checking");
        void checkPwned(password)
            .then((count) => setPwned({ count }))
            .catch(() => setPwned("error"));
    };

    const entry = query.data;

    return (
        <Dialog
            open={open}
            onClose={onClose}
            title={entry?.title ?? t("entry.loading")}
            footer={
                <>
                    <Button variant="destructive" onClick={onDelete}>
                        <Trash2 size={16} />
                        {t("entry.delete")}
                    </Button>
                    <Button variant="outline" onClick={onEdit}>
                        <Pencil size={16} />
                        {t("entry.edit")}
                    </Button>
                </>
            }
        >
            {query.isLoading && <p className="text-sm text-muted-foreground">{t("entry.loading")}</p>}
            {query.isError && <p className="text-sm text-destructive">{t("errors.generic")}</p>}
            {entry && (
                <div className="flex flex-col gap-4">
                    {entry.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1.5">
                            {entry.tags
                                .map((id) => (tagsQuery.data ?? []).find((tg) => tg.id === id)?.name)
                                .filter((n): n is string => !!n)
                                .map((name) => (
                                    <span
                                        key={name}
                                        className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground"
                                    >
                                        {name}
                                    </span>
                                ))}
                        </div>
                    )}
                    <ReadField label={t("entry.username")} value={entry.username}>
                        {entry.username && (
                            <IconButton label={t("entry.copy")} onClick={() => copy(entry.username)}>
                                <Copy size={16} />
                            </IconButton>
                        )}
                    </ReadField>

                    <ReadField
                        label={t("entry.password")}
                        value={revealed ? entry.password : "•".repeat(Math.min(entry.password.length, 16))}
                        mono
                    >
                        {entry.password && (
                            <>
                                <IconButton
                                    label={revealed ? t("common.hide") : t("common.show")}
                                    onClick={() => setRevealed((r) => !r)}
                                >
                                    {revealed ? <EyeOff size={16} /> : <Eye size={16} />}
                                </IconButton>
                                <IconButton label={t("entry.copy")} onClick={() => copy(entry.password)}>
                                    <Copy size={16} />
                                </IconButton>
                            </>
                        )}
                    </ReadField>

                    {entry.password && (
                        <BreachCheck state={pwned} onCheck={() => runBreachCheck(entry.password)} />
                    )}

                    {entry.password && settings.passwordExpiryDays > 0 && (() => {
                        const ageDays = Math.floor((Date.now() - entry.updatedAtMs) / 86_400_000);
                        return ageDays >= settings.passwordExpiryDays ? (
                            <p className="flex items-center gap-1.5 rounded-md bg-yellow-500/10 px-2 py-1.5 text-xs text-yellow-700 dark:text-yellow-400">
                                <Timer size={14} />
                                {t("entry.expiry_warning", { days: ageDays })}
                            </p>
                        ) : null;
                    })()}

                    {entry.url && (
                        <ReadField label={t("entry.url")} value={entry.url}>
                            <IconButton
                                label={t("entry.open_browser")}
                                onClick={() => {
                                    void openExternal(entry.url ?? "").catch(() => {});
                                }}
                            >
                                <ExternalLink size={16} />
                            </IconButton>
                            <IconButton label={t("entry.copy")} onClick={() => copy(entry.url ?? "")}>
                                <Copy size={16} />
                            </IconButton>
                        </ReadField>
                    )}
                    {entry.appName && <ReadField label={t("entry.app_name")} value={entry.appName} />}
                    {entry.notes && <ReadField label={t("entry.notes")} value={entry.notes} multiline />}
                    {entry.totpSecret && (
                        <TotpDisplay secret={entry.totpSecret} onCopyCode={copy} />
                    )}

                    {entry.customFields.map((field, i) => (
                        <CustomFieldRow key={i} field={field} onCopy={copy} />
                    ))}

                    <PasswordHistorySection entryId={entry.id} open={open} onCopy={copy} />
                    <AttachmentsSection entryId={entry.id} open={open} />
                </div>
            )}
        </Dialog>
    );
}

/** Human-readable byte size (e.g. "3.2 KB"). */
function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    const kb = bytes / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    return `${(kb / 1024).toFixed(1)} MB`;
}

/**
 * Encrypted attachments for an entry. Picker selections and downloads are
 * path-based, so those bytes stay in Rust; drag-and-dropped files arrive as
 * bytes in the webview (no OS path is exposed there) and are sealed + zeroized
 * in Rust. Supports selecting multiple files at once and dropping them in.
 */
function AttachmentsSection({ entryId, open }: { entryId: string; open: boolean }) {
    const { t } = useTranslation();
    const qc = useQueryClient();
    const [busy, setBusy] = useState(false);
    const [errorKey, setErrorKey] = useState<string | null>(null);
    const [dragOver, setDragOver] = useState(false);

    const query = useQuery({
        queryKey: ["attachments", entryId],
        queryFn: () => listAttachments(entryId),
        enabled: open,
    });

    const refresh = () => qc.invalidateQueries({ queryKey: ["attachments", entryId] });

    // While this section is mounted, stop the webview from navigating to / opening
    // a file dropped anywhere outside the drop zone below.
    useEffect(() => {
        const swallow = (e: DragEvent) => {
            if (e.dataTransfer?.types.includes("Files")) e.preventDefault();
        };
        window.addEventListener("dragover", swallow);
        window.addEventListener("drop", swallow);
        return () => {
            window.removeEventListener("dragover", swallow);
            window.removeEventListener("drop", swallow);
        };
    }, []);

    // Picker selections are path-based, so the plaintext bytes stay in Rust.
    const addPaths = async (paths: string[]) => {
        setBusy(true);
        try {
            for (const path of paths) {
                await addAttachment(entryId, path);
            }
            await refresh();
        } catch (e) {
            setErrorKey(`errors.${asCommandError(e).kind}`);
        } finally {
            setBusy(false);
        }
    };

    // Dropped files arrive as bytes (the OS path is not exposed to the webview).
    const addFiles = async (files: File[]) => {
        setBusy(true);
        try {
            for (const file of files) {
                if (file.size > MAX_ATTACHMENT_SIZE) {
                    setErrorKey("attachment.too_large");
                    continue;
                }
                const bytes = new Uint8Array(await file.arrayBuffer());
                await addAttachmentBytes(entryId, file.name, bytes);
            }
            await refresh();
        } catch (e) {
            setErrorKey(`errors.${asCommandError(e).kind}`);
        } finally {
            setBusy(false);
        }
    };

    const pick = async () => {
        setErrorKey(null);
        const picked = await openFileDialog({ multiple: true });
        if (picked === null) return;
        await addPaths(Array.isArray(picked) ? picked : [picked]);
    };

    const onDrop = (e: React.DragEvent) => {
        e.preventDefault();
        setDragOver(false);
        setErrorKey(null);
        const files = Array.from(e.dataTransfer.files);
        if (files.length > 0) void addFiles(files);
    };

    const saveOne = async (att: AttachmentMeta) => {
        setErrorKey(null);
        const path = await saveFileDialog({ defaultPath: att.name });
        if (typeof path !== "string") return;
        try {
            await saveAttachment(att.id, path);
        } catch (e) {
            setErrorKey(`errors.${asCommandError(e).kind}`);
        }
    };

    const removeOne = async (id: string) => {
        try {
            await deleteAttachment(id);
            await refresh();
        } catch (e) {
            setErrorKey(`errors.${asCommandError(e).kind}`);
        }
    };

    const items = query.data ?? [];

    return (
        <div
            onDragOver={(e) => {
                if (!e.dataTransfer.types.includes("Files")) return;
                e.preventDefault();
                setDragOver(true);
            }}
            onDragLeave={(e) => {
                if (e.currentTarget.contains(e.relatedTarget as Node)) return;
                setDragOver(false);
            }}
            onDrop={onDrop}
            className={`flex flex-col gap-1.5 rounded-md p-1 transition-colors ${
                dragOver ? "ring-2 ring-primary" : ""
            }`}
        >
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {t("attachment.section")}
            </span>
            <ul className="flex flex-col gap-1">
                {items.map((att) => (
                    <li
                        key={att.id}
                        className="flex items-center gap-2 rounded border border-border px-2 py-1"
                    >
                        <Paperclip size={14} className="shrink-0 text-muted-foreground" />
                        <span className="min-w-0 flex-1 truncate text-sm">{att.name}</span>
                        <span className="shrink-0 text-[10px] tabular-nums text-muted-foreground">
                            {formatSize(att.size)}
                        </span>
                        <IconButton label={t("attachment.save")} onClick={() => void saveOne(att)}>
                            <Download size={14} />
                        </IconButton>
                        <IconButton
                            label={t("attachment.delete")}
                            onClick={() => void removeOne(att.id)}
                        >
                            <Trash2 size={14} />
                        </IconButton>
                    </li>
                ))}
            </ul>
            {query.isSuccess && items.length === 0 && (
                <p className="text-xs text-muted-foreground">{t("attachment.empty")}</p>
            )}
            <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">{t("attachment.drop_hint")}</span>
                <Button variant="outline" disabled={busy} onClick={() => void pick()}>
                    <Plus size={16} />
                    {t("attachment.add")}
                </Button>
            </div>
            {errorKey && <p className="text-xs text-destructive">{t(errorKey)}</p>}
        </div>
    );
}

function PasswordHistorySection({
    entryId,
    open,
    onCopy,
}: {
    entryId: string;
    open: boolean;
    onCopy: (value: string) => void;
}) {
    const { t } = useTranslation();
    const qc = useQueryClient();
    const [show, setShow] = useState(false);

    const query = useQuery({
        queryKey: ["entry-history", entryId],
        queryFn: () => passwordHistory(entryId),
        enabled: open && show,
        gcTime: 0,
        staleTime: 0,
    });

    // Collapse and evict the decrypted history when the dialog closes.
    useEffect(() => {
        if (!open) {
            setShow(false);
            qc.removeQueries({ queryKey: ["entry-history", entryId] });
        }
    }, [open, entryId, qc]);

    if (!show) {
        return (
            <button
                type="button"
                onClick={() => setShow(true)}
                className="self-start text-xs text-muted-foreground underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
                {t("entry.history_show")}
            </button>
        );
    }

    const items = query.data ?? [];
    return (
        <div className="flex flex-col gap-1.5">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {t("entry.history")}
            </span>
            {query.isLoading && <p className="text-xs text-muted-foreground">{t("entry.loading")}</p>}
            {query.isSuccess && items.length === 0 && (
                <p className="text-xs text-muted-foreground">{t("entry.history_empty")}</p>
            )}
            <ul className="flex flex-col gap-1">
                {items.map((item, i) => (
                    <HistoryRow key={i} item={item} onCopy={onCopy} />
                ))}
            </ul>
        </div>
    );
}

function HistoryRow({
    item,
    onCopy,
}: {
    item: PasswordHistoryItem;
    onCopy: (value: string) => void;
}) {
    const { t } = useTranslation();
    const [revealed, setRevealed] = useState(false);
    const when = new Date(item.changedAtMs).toLocaleString();
    return (
        <li className="flex items-center gap-2 rounded border border-border px-2 py-1">
            <span className="min-w-0 flex-1 truncate font-mono text-xs">
                {revealed ? item.password : "•".repeat(Math.min(item.password.length, 16))}
            </span>
            <span className="shrink-0 text-[10px] tabular-nums text-muted-foreground">{when}</span>
            <IconButton
                label={revealed ? t("common.hide") : t("common.show")}
                onClick={() => setRevealed((r) => !r)}
            >
                {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
            </IconButton>
            <IconButton label={t("entry.copy")} onClick={() => onCopy(item.password)}>
                <Copy size={14} />
            </IconButton>
        </li>
    );
}

function CustomFieldRow({ field, onCopy }: { field: CustomField; onCopy: (v: string) => void }) {
    const { t } = useTranslation();
    const [revealed, setRevealed] = useState(false);
    const masked = field.hidden && !revealed;
    return (
        <ReadField
            label={field.label || t("field.custom")}
            value={masked ? "•".repeat(Math.min(field.value.length, 16)) : field.value}
            mono={field.hidden}
        >
            {field.value && (
                <>
                    {field.hidden && (
                        <IconButton
                            label={revealed ? t("common.hide") : t("common.show")}
                            onClick={() => setRevealed((r) => !r)}
                        >
                            {revealed ? <EyeOff size={16} /> : <Eye size={16} />}
                        </IconButton>
                    )}
                    <IconButton label={t("entry.copy")} onClick={() => onCopy(field.value)}>
                        <Copy size={16} />
                    </IconButton>
                </>
            )}
        </ReadField>
    );
}

function BreachCheck({ state, onCheck }: { state: PwnedState; onCheck: () => void }) {
    const { t } = useTranslation();

    if (state === "idle") {
        return (
            <Button variant="outline" className="self-start" onClick={onCheck}>
                <ShieldQuestion size={16} />
                {t("entry.check_breaches")}
            </Button>
        );
    }
    if (state === "checking") {
        return (
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <ShieldQuestion size={14} />
                {t("entry.breach_checking")}
            </p>
        );
    }
    if (state === "error") {
        return <p className="text-xs text-destructive">{t("errors.network")}</p>;
    }
    if (state.count === 0) {
        return (
            <p className="flex items-center gap-1.5 text-xs text-green-600 dark:text-green-400">
                <ShieldCheck size={14} />
                {t("entry.breach_safe")}
            </p>
        );
    }
    return (
        <p className="flex items-center gap-1.5 text-xs font-medium text-destructive">
            <ShieldAlert size={14} />
            {t("entry.breach_pwned", { count: state.count })}
        </p>
    );
}

function TotpDisplay({
    secret,
    onCopyCode,
}: {
    secret: string;
    onCopyCode: (code: string) => void;
}) {
    const { t } = useTranslation();
    const [code, setCode] = useState<string | null>(null);
    const [period, setPeriod] = useState(30);
    const [remaining, setRemaining] = useState(0);
    const [error, setError] = useState(false);

    const refresh = useCallback(async () => {
        try {
            const r = await generateTotp(secret);
            setCode(r.code);
            setPeriod(r.period);
            setRemaining(r.remaining);
            setError(false);
        } catch {
            setError(true);
            setCode(null);
        }
    }, [secret]);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    useEffect(() => {
        const id = window.setInterval(() => {
            setRemaining((r) => {
                if (r <= 1) {
                    void refresh();
                    return period;
                }
                return r - 1;
            });
        }, 1000);
        return () => window.clearInterval(id);
    }, [refresh, period]);

    if (error) {
        return <p className="text-xs text-destructive">{t("entry.totp_error")}</p>;
    }
    if (code === null) {
        return <p className="text-xs text-muted-foreground">{t("entry.loading")}</p>;
    }
    const formatted = code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;

    return (
        <ReadField label={t("entry.totp")} value={formatted} mono>
            <span className="inline-flex items-center gap-1 text-xs tabular-nums text-muted-foreground">
                <Timer size={14} />
                {remaining}s
            </span>
            <IconButton label={t("entry.copy")} onClick={() => onCopyCode(code)}>
                <Copy size={16} />
            </IconButton>
        </ReadField>
    );
}

function ReadField({
    label,
    value,
    mono,
    multiline,
    children,
}: {
    label: string;
    value: string;
    mono?: boolean;
    multiline?: boolean;
    children?: React.ReactNode;
}) {
    return (
        <div className="flex flex-col gap-1">
            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {label}
            </span>
            <div className="flex items-start justify-between gap-2">
                <span
                    className={`min-w-0 flex-1 break-words text-sm ${mono ? "font-mono" : ""} ${
                        multiline ? "whitespace-pre-wrap" : ""
                    }`}
                >
                    {value || "—"}
                </span>
                {children && <div className="flex shrink-0 items-center gap-1">{children}</div>}
            </div>
        </div>
    );
}

function IconButton({
    label,
    onClick,
    children,
}: {
    label: string;
    onClick: () => void;
    children: React.ReactNode;
}) {
    return (
        <button
            type="button"
            onClick={onClick}
            aria-label={label}
            title={label}
            className="rounded p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
            {children}
        </button>
    );
}
