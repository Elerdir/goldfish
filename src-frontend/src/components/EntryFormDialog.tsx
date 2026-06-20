import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { Paperclip, Plus, Trash2, Wand2 } from "lucide-react";
import { useTranslation } from "react-i18next";

import { PasswordGenerator } from "@/components/PasswordGenerator";
import { PasswordInput } from "@/components/PasswordInput";
import { PasswordStrength } from "@/components/PasswordStrength";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
    addAttachment,
    addEntry,
    asCommandError,
    createFolder,
    createTag,
    getEntry,
    isTauri,
    listFolders,
    listTags,
    updateEntry,
    type CustomField,
    type EntryInput,
    type EntryKind,
} from "@/lib/tauri";
import { cn } from "@/lib/utils";

const KINDS: EntryKind[] = ["login", "note", "card", "ssh", "token"];

interface EntryFormDialogProps {
    open: boolean;
    /** When set, the dialog edits this entry; otherwise it creates a new one. */
    entryId: string | null;
    onClose: () => void;
    onSaved: () => void;
    /** Render as a full-window panel (hosted in its own OS window). */
    fullWindow?: boolean;
}

interface FormState {
    kind: EntryKind;
    title: string;
    username: string;
    password: string;
    url: string;
    appName: string;
    notes: string;
    description: string;
    totpSecret: string;
    folderId: string;
    favorite: boolean;
    customFields: CustomField[];
    tags: string[];
}

const EMPTY: FormState = {
    kind: "login",
    title: "",
    username: "",
    password: "",
    url: "",
    appName: "",
    notes: "",
    description: "",
    totpSecret: "",
    folderId: "",
    favorite: false,
    customFields: [],
    tags: [],
};

function toInput(form: FormState): EntryInput {
    const orNull = (s: string) => (s.trim() === "" ? null : s);
    return {
        kind: form.kind,
        title: form.title.trim(),
        username: form.username,
        password: form.password,
        url: orNull(form.url),
        appName: orNull(form.appName),
        notes: orNull(form.notes),
        description: orNull(form.description),
        totpSecret: orNull(form.totpSecret),
        folderId: form.folderId === "" ? null : form.folderId,
        favorite: form.favorite,
        // Drop rows the user left entirely blank.
        customFields: form.customFields.filter(
            (f) => f.label.trim() !== "" || f.value !== "",
        ),
        tags: form.tags,
    };
}

export function EntryFormDialog({
    open,
    entryId,
    onClose,
    onSaved,
    fullWindow,
}: EntryFormDialogProps) {
    const { t } = useTranslation();
    const qc = useQueryClient();
    const [form, setForm] = useState<FormState>(EMPTY);
    const [errorKey, setErrorKey] = useState<string | null>(null);
    const [genOpen, setGenOpen] = useState(false);
    const [addingFolder, setAddingFolder] = useState(false);
    const [newFolderName, setNewFolderName] = useState("");
    // Files queued in the form; attached to the entry right after it is saved
    // (a new entry has no id to attach to until then).
    const [pendingPaths, setPendingPaths] = useState<string[]>([]);
    const [dragOver, setDragOver] = useState(false);

    const editing = entryId !== null;

    // Prefill when editing. Don't cache the decrypted secrets beyond this use.
    const detailQuery = useQuery({
        queryKey: ["entry", entryId],
        queryFn: () => getEntry(entryId as string),
        enabled: open && editing,
        gcTime: 0,
        staleTime: 0,
    });

    // Drop the decrypted entry from the cache once the form closes.
    useEffect(() => {
        if (!open && entryId !== null) {
            qc.removeQueries({ queryKey: ["entry", entryId] });
        }
    }, [open, entryId, qc]);

    // Clear queued attachments whenever a different entry/form opens.
    useEffect(() => {
        setPendingPaths([]);
    }, [open, entryId]);

    // OS file drag-and-drop onto the entry window queues files (by path, so the
    // bytes are read and sealed in Rust, never in the webview).
    useEffect(() => {
        if (!isTauri()) return;
        let unlisten: (() => void) | undefined;
        let cancelled = false;
        void getCurrentWebview()
            .onDragDropEvent((event) => {
                const p = event.payload;
                if (p.type === "drop") {
                    setDragOver(false);
                    if (p.paths.length > 0) {
                        setPendingPaths((prev) => [...prev, ...p.paths]);
                    }
                } else if (p.type === "leave") {
                    setDragOver(false);
                } else {
                    setDragOver(true);
                }
            })
            .then((un) => {
                if (cancelled) un();
                else unlisten = un;
            });
        return () => {
            cancelled = true;
            unlisten?.();
        };
    }, []);

    useEffect(() => {
        if (!open) return;
        if (editing && detailQuery.data) {
            const e = detailQuery.data;
            setForm({
                kind: e.kind,
                title: e.title,
                username: e.username,
                password: e.password,
                url: e.url ?? "",
                appName: e.appName ?? "",
                notes: e.notes ?? "",
                description: e.description ?? "",
                totpSecret: e.totpSecret ?? "",
                folderId: e.folderId ?? "",
                favorite: e.favorite,
                customFields: e.customFields,
                tags: e.tags,
            });
        } else if (!editing) {
            setForm(EMPTY);
        }
        setErrorKey(null);
    }, [open, editing, detailQuery.data]);

    const foldersQuery = useQuery({
        queryKey: ["folders"],
        queryFn: listFolders,
        enabled: open,
    });

    const tagsQuery = useQuery({ queryKey: ["tags"], queryFn: listTags, enabled: open });
    const [newTagName, setNewTagName] = useState("");

    const toggleTag = (id: string) =>
        setForm((f) => ({
            ...f,
            tags: f.tags.includes(id) ? f.tags.filter((t) => t !== id) : [...f.tags, id],
        }));

    const createNewTag = async () => {
        const name = newTagName.trim();
        setNewTagName("");
        if (!name) return;
        try {
            const tag = await createTag(name);
            await qc.invalidateQueries({ queryKey: ["tags"] });
            setForm((f) => ({ ...f, tags: [...f.tags, tag.id] }));
        } catch (e) {
            setErrorKey(`errors.${asCommandError(e).kind}`);
        }
    };

    const mutation = useMutation({
        mutationFn: async (input: EntryInput) => {
            const saved =
                entryId !== null ? await updateEntry(entryId, input) : await addEntry(input);
            // The entry now has an id, so attach any files queued in the form.
            for (const path of pendingPaths) {
                await addAttachment(saved.id, path);
            }
            return saved;
        },
        onSuccess: () => {
            void qc.invalidateQueries({ queryKey: ["entries"] });
            if (editing) void qc.invalidateQueries({ queryKey: ["entry", entryId] });
            onSaved();
        },
        onError: (err) => setErrorKey(`errors.${asCommandError(err).kind}`),
    });

    const update = <K extends keyof FormState>(key: K, value: FormState[K]) =>
        setForm((f) => ({ ...f, [key]: value }));

    // Suggested starter fields when picking a kind (only applied if none yet).
    const templateFor = (kind: EntryKind): CustomField[] => {
        const f = (label: string, hidden: boolean): CustomField => ({ label, value: "", hidden });
        switch (kind) {
            case "card":
                return [
                    f(t("field.card_number"), true),
                    f(t("field.expiry"), false),
                    f(t("field.cvv"), true),
                    f(t("field.cardholder"), false),
                ];
            case "ssh":
                return [
                    f(t("field.private_key"), true),
                    f(t("field.public_key"), false),
                    f(t("field.passphrase"), true),
                ];
            case "token":
                return [f(t("field.token"), true), f(t("field.endpoint"), false)];
            default:
                return [];
        }
    };

    const changeKind = (kind: EntryKind) =>
        setForm((f) => ({
            ...f,
            kind,
            customFields: f.customFields.length === 0 ? templateFor(kind) : f.customFields,
        }));

    const addField = () =>
        setForm((f) => ({
            ...f,
            customFields: [...f.customFields, { label: "", value: "", hidden: true }],
        }));

    const updateField = (index: number, patch: Partial<CustomField>) =>
        setForm((f) => ({
            ...f,
            customFields: f.customFields.map((cf, j) => (j === index ? { ...cf, ...patch } : cf)),
        }));

    const removeField = (index: number) =>
        setForm((f) => ({
            ...f,
            customFields: f.customFields.filter((_, j) => j !== index),
        }));

    const baseName = (p: string) => p.split(/[\\/]/).pop() || p;

    const pickFiles = async () => {
        setErrorKey(null);
        const picked = await openFileDialog({ multiple: true });
        if (picked === null) return;
        setPendingPaths((prev) => [...prev, ...(Array.isArray(picked) ? picked : [picked])]);
    };

    const removePending = (i: number) =>
        setPendingPaths((prev) => prev.filter((_, j) => j !== i));

    const createNewFolder = async () => {
        const name = newFolderName.trim();
        if (!name) {
            setAddingFolder(false);
            return;
        }
        try {
            const folder = await createFolder(name);
            await qc.invalidateQueries({ queryKey: ["folders"] });
            update("folderId", folder.id);
        } catch (e) {
            setErrorKey(`errors.${asCommandError(e).kind}`);
        } finally {
            setAddingFolder(false);
            setNewFolderName("");
        }
    };

    const canSubmit = form.title.trim().length > 0 && !mutation.isPending;

    return (
        <Dialog
            open={open}
            onClose={onClose}
            fullWindow={fullWindow}
            title={editing ? t("form.edit_title") : t("form.add_title")}
            footer={
                <>
                    <Button variant="ghost" onClick={onClose}>
                        {t("entry.cancel")}
                    </Button>
                    <Button disabled={!canSubmit} onClick={() => mutation.mutate(toInput(form))}>
                        {mutation.isPending ? t("entry.saving") : t("entry.save")}
                    </Button>
                </>
            }
        >
            <div className="flex flex-col gap-4">
                <Field label={t("entrykind.label")}>
                    <select
                        value={form.kind}
                        onChange={(e) => changeKind(e.target.value as EntryKind)}
                        className="h-9 w-full rounded-md border border-border bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                        {KINDS.map((k) => (
                            <option key={k} value={k}>
                                {t(`entrykind.${k}`)}
                            </option>
                        ))}
                    </select>
                </Field>
                <Field label={t("entry.title")} required>
                    <Input
                        value={form.title}
                        onChange={(e) => update("title", e.target.value)}
                        autoFocus
                    />
                </Field>
                <Field label={t("entry.username")}>
                    <Input
                        value={form.username}
                        onChange={(e) => update("username", e.target.value)}
                        autoComplete="off"
                    />
                </Field>
                <Field label={t("entry.password")}>
                    <div className="flex gap-2">
                        <div className="flex-1">
                            <PasswordInput
                                id="entry-password"
                                value={form.password}
                                onChange={(e) => update("password", e.target.value)}
                                autoComplete="off"
                            />
                        </div>
                        <Button
                            variant="outline"
                            onClick={() => setGenOpen((o) => !o)}
                            aria-label={t("generator.title")}
                            title={t("generator.title")}
                            className="px-3"
                        >
                            <Wand2 size={16} />
                        </Button>
                    </div>
                    {form.password.length > 0 && (
                        <div className="mt-2">
                            <PasswordStrength password={form.password} />
                        </div>
                    )}
                    {genOpen && (
                        <PasswordGenerator onGenerate={(pw) => update("password", pw)} />
                    )}
                </Field>
                <div className="grid grid-cols-2 gap-3">
                    <Field label={t("entry.url")}>
                        <Input
                            value={form.url}
                            onChange={(e) => update("url", e.target.value)}
                            placeholder="https://"
                        />
                    </Field>
                    <Field label={t("entry.app_name")}>
                        <Input
                            value={form.appName}
                            onChange={(e) => update("appName", e.target.value)}
                        />
                    </Field>
                </div>
                <Field label={t("entry.notes")}>
                    <Textarea value={form.notes} onChange={(e) => update("notes", e.target.value)} />
                </Field>
                <Field label={t("folder.label")}>
                    {addingFolder ? (
                        <div className="flex gap-2">
                            <Input
                                value={newFolderName}
                                onChange={(e) => setNewFolderName(e.target.value)}
                                placeholder={t("folder.new_placeholder")}
                                autoFocus
                                onKeyDown={(e) => {
                                    if (e.key === "Enter") void createNewFolder();
                                    if (e.key === "Escape") {
                                        setAddingFolder(false);
                                        setNewFolderName("");
                                    }
                                }}
                            />
                            <Button variant="outline" className="px-3" onClick={() => void createNewFolder()}>
                                {t("entry.save")}
                            </Button>
                        </div>
                    ) : (
                        <div className="flex gap-2">
                            <select
                                value={form.folderId}
                                onChange={(e) => update("folderId", e.target.value)}
                                className="h-9 w-full rounded-md border border-border bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                            >
                                <option value="">{t("folder.none")}</option>
                                {(foldersQuery.data ?? []).map((f) => (
                                    <option key={f.id} value={f.id}>
                                        {f.name}
                                    </option>
                                ))}
                            </select>
                            <Button
                                variant="outline"
                                className="px-3"
                                onClick={() => setAddingFolder(true)}
                                aria-label={t("folder.new")}
                                title={t("folder.new")}
                            >
                                <Plus size={16} />
                            </Button>
                        </div>
                    )}
                </Field>
                <Field label={t("tag.label")}>
                    <div className="flex flex-col gap-2">
                        {(tagsQuery.data ?? []).length > 0 && (
                            <div className="flex flex-wrap gap-1.5">
                                {(tagsQuery.data ?? []).map((tag) => {
                                    const on = form.tags.includes(tag.id);
                                    return (
                                        <button
                                            key={tag.id}
                                            type="button"
                                            onClick={() => toggleTag(tag.id)}
                                            className={cn(
                                                "rounded-full border px-2.5 py-0.5 text-xs transition-colors",
                                                on
                                                    ? "border-primary bg-primary text-primary-foreground"
                                                    : "border-border hover:bg-accent",
                                            )}
                                        >
                                            {tag.name}
                                        </button>
                                    );
                                })}
                            </div>
                        )}
                        <div className="flex gap-2">
                            <Input
                                value={newTagName}
                                onChange={(e) => setNewTagName(e.target.value)}
                                placeholder={t("tag.new_placeholder")}
                                onKeyDown={(e) => {
                                    if (e.key === "Enter") {
                                        e.preventDefault();
                                        void createNewTag();
                                    }
                                }}
                            />
                            <Button
                                variant="outline"
                                className="px-3"
                                onClick={() => void createNewTag()}
                                aria-label={t("tag.new")}
                                title={t("tag.new")}
                            >
                                <Plus size={16} />
                            </Button>
                        </div>
                    </div>
                </Field>
                <Field label={t("field.custom")}>
                    <div className="flex flex-col gap-2">
                        {form.customFields.map((cf, i) => (
                            <div key={i} className="flex items-center gap-1.5">
                                <Input
                                    value={cf.label}
                                    onChange={(e) => updateField(i, { label: e.target.value })}
                                    placeholder={t("field.label_placeholder")}
                                    className="w-1/3"
                                />
                                <div className="flex-1">
                                    {cf.hidden ? (
                                        <PasswordInput
                                            id={`cf-${i}`}
                                            value={cf.value}
                                            onChange={(e) => updateField(i, { value: e.target.value })}
                                            autoComplete="off"
                                        />
                                    ) : (
                                        <Input
                                            value={cf.value}
                                            onChange={(e) => updateField(i, { value: e.target.value })}
                                            autoComplete="off"
                                        />
                                    )}
                                </div>
                                <input
                                    type="checkbox"
                                    checked={cf.hidden}
                                    onChange={(e) => updateField(i, { hidden: e.target.checked })}
                                    title={t("field.hidden")}
                                    aria-label={t("field.hidden")}
                                    className="h-4 w-4 accent-primary"
                                />
                                <button
                                    type="button"
                                    onClick={() => removeField(i)}
                                    aria-label={t("field.remove")}
                                    title={t("field.remove")}
                                    className="rounded p-1.5 text-muted-foreground transition-colors hover:text-destructive"
                                >
                                    <Trash2 size={16} />
                                </button>
                            </div>
                        ))}
                        <Button variant="outline" onClick={addField} className="self-start">
                            <Plus size={16} />
                            {t("field.add")}
                        </Button>
                    </div>
                </Field>
                <Field label={t("entry.totp_key")}>
                    <Input
                        value={form.totpSecret}
                        onChange={(e) => update("totpSecret", e.target.value)}
                        placeholder={t("entry.totp_placeholder")}
                        autoComplete="off"
                        spellCheck={false}
                        className="font-mono"
                    />
                </Field>
                <Field label={t("attachment.section")}>
                    <div
                        className={cn(
                            "flex flex-col gap-2 rounded-md p-1 transition-colors",
                            dragOver && "ring-2 ring-primary",
                        )}
                    >
                        {pendingPaths.length > 0 && (
                            <ul className="flex flex-col gap-1">
                                {pendingPaths.map((p, i) => (
                                    <li
                                        key={`${p}-${i}`}
                                        className="flex items-center gap-2 rounded border border-border px-2 py-1"
                                    >
                                        <Paperclip
                                            size={14}
                                            className="shrink-0 text-muted-foreground"
                                        />
                                        <span className="min-w-0 flex-1 truncate text-sm">
                                            {baseName(p)}
                                        </span>
                                        <button
                                            type="button"
                                            onClick={() => removePending(i)}
                                            aria-label={t("attachment.delete")}
                                            title={t("attachment.delete")}
                                            className="rounded p-1 text-muted-foreground transition-colors hover:text-destructive"
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        )}
                        <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">
                                {t("attachment.drop_hint")}
                            </span>
                            <Button variant="outline" onClick={() => void pickFiles()}>
                                <Plus size={16} />
                                {t("attachment.add")}
                            </Button>
                        </div>
                        <p className="text-xs text-muted-foreground">
                            {t("attachment.attach_on_save")}
                        </p>
                    </div>
                </Field>
                <label className="flex items-center gap-2 text-sm">
                    <input
                        type="checkbox"
                        checked={form.favorite}
                        onChange={(e) => update("favorite", e.target.checked)}
                        className="h-4 w-4 accent-primary"
                    />
                    {t("entry.favorite")}
                </label>
                {errorKey && <p className="text-sm text-destructive">{t(errorKey)}</p>}
            </div>
        </Dialog>
    );
}

function Field({
    label,
    required,
    children,
}: {
    label: string;
    required?: boolean;
    children: React.ReactNode;
}) {
    return (
        <div className="flex flex-col gap-1.5">
            <Label>
                {label}
                {required && <span className="ml-0.5 text-destructive">*</span>}
            </Label>
            {children}
        </div>
    );
}
