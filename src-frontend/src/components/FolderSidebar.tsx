import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { useTranslation } from "react-i18next";

import { appearanceTextStyle } from "@/lib/appearance";
import { ENTRY_MIME, draggedEntryId } from "@/lib/dnd";
import {
    createFolder,
    deleteFolder,
    listFolders,
    moveEntryToFolder,
    renameFolder,
    type Appearance,
} from "@/lib/tauri";
import { cn } from "@/lib/utils";

/**
 * Left rail listing folders. Selecting one filters the entry list; folders can be
 * added, renamed (pencil), and deleted (trash — entries are kept, just unfiled).
 */
export function FolderSidebar({
    selected,
    onSelect,
}: {
    selected: string | null;
    onSelect: (id: string | null) => void;
}) {
    const { t } = useTranslation();
    const qc = useQueryClient();
    const foldersQuery = useQuery({ queryKey: ["folders"], queryFn: listFolders });

    const [adding, setAdding] = useState(false);
    const [newName, setNewName] = useState("");
    const [editingId, setEditingId] = useState<string | null>(null);
    const [editName, setEditName] = useState("");

    const refresh = () => {
        void qc.invalidateQueries({ queryKey: ["folders"] });
        void qc.invalidateQueries({ queryKey: ["entries"] });
    };

    const add = async () => {
        const name = newName.trim();
        setAdding(false);
        setNewName("");
        if (!name) return;
        try {
            await createFolder(name);
            refresh();
        } catch {
            /* surfaced elsewhere; keep the rail quiet */
        }
    };

    const rename = async (id: string) => {
        const name = editName.trim();
        setEditingId(null);
        if (!name) return;
        try {
            await renameFolder(id, name);
            refresh();
        } catch {
            /* ignore */
        }
    };

    const remove = async (id: string) => {
        try {
            await deleteFolder(id);
            if (selected === id) onSelect(null);
            refresh();
        } catch {
            /* ignore */
        }
    };

    // Drop an entry onto a folder to move it there; onto "All entries" to unfile.
    const moveHere = async (entryId: string, target: string | null) => {
        try {
            await moveEntryToFolder(entryId, target);
            refresh();
        } catch {
            /* ignore */
        }
    };

    const folders = foldersQuery.data ?? [];

    return (
        <aside className="flex w-52 shrink-0 flex-col gap-0.5 overflow-y-auto rounded-xl border border-border bg-card/60 p-3 shadow-sm">
            <FolderItem
                label={t("folder.all")}
                active={selected === null}
                onClick={() => onSelect(null)}
                onMoveHere={(id) => void moveHere(id, null)}
            />
            {folders.map((f) =>
                editingId === f.id ? (
                    <input
                        key={f.id}
                        autoFocus
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === "Enter") void rename(f.id);
                            if (e.key === "Escape") setEditingId(null);
                        }}
                        onBlur={() => void rename(f.id)}
                        className="rounded-md border border-border bg-background px-2 py-1 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    />
                ) : (
                    <div key={f.id} className="group flex items-center gap-0.5">
                        <FolderItem
                            label={f.name}
                            active={selected === f.id}
                            appearance={f.appearance}
                            onClick={() => onSelect(f.id)}
                            onMoveHere={(id) => void moveHere(id, f.id)}
                        />
                        <RailIcon
                            label={t("folder.rename")}
                            onClick={() => {
                                setEditingId(f.id);
                                setEditName(f.name);
                            }}
                        >
                            <Pencil size={13} />
                        </RailIcon>
                        <RailIcon label={t("folder.delete")} onClick={() => void remove(f.id)}>
                            <Trash2 size={13} />
                        </RailIcon>
                    </div>
                ),
            )}
            {adding ? (
                <input
                    autoFocus
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    onKeyDown={(e) => {
                        if (e.key === "Enter") void add();
                        if (e.key === "Escape") {
                            setAdding(false);
                            setNewName("");
                        }
                    }}
                    onBlur={() => void add()}
                    placeholder={t("folder.new_placeholder")}
                    className="mt-1 rounded-md border border-border bg-background px-2 py-1 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                />
            ) : (
                <button
                    type="button"
                    onClick={() => setAdding(true)}
                    className="mt-1 flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                >
                    <Plus size={14} />
                    {t("folder.new")}
                </button>
            )}
        </aside>
    );
}

function FolderItem({
    label,
    active,
    appearance,
    onClick,
    onMoveHere,
}: {
    label: string;
    active: boolean;
    /** Per-folder visual overrides, mirrored from the content panel. */
    appearance?: Appearance;
    onClick: () => void;
    /** Called with the dropped entry's id when one is dragged onto this item. */
    onMoveHere?: (entryId: string) => void;
}) {
    const [over, setOver] = useState(false);

    // During `dragover` the payload is not yet readable, so we gate on the type
    // list; the id is only pulled out on `drop`.
    const accepts = (e: React.DragEvent) => e.dataTransfer.types.includes(ENTRY_MIME);

    // Reflect the folder's own appearance on its rail item too.
    const style: React.CSSProperties | undefined = appearance
        ? { background: appearance.background ?? undefined, ...appearanceTextStyle(appearance) }
        : undefined;
    const customBg = !!appearance?.background;

    return (
        <button
            type="button"
            style={style}
            onClick={onClick}
            aria-current={active ? "true" : undefined}
            onDragOver={
                onMoveHere
                    ? (e) => {
                          if (!accepts(e)) return;
                          e.preventDefault();
                          e.dataTransfer.dropEffect = "move";
                          setOver(true);
                      }
                    : undefined
            }
            onDragLeave={onMoveHere ? () => setOver(false) : undefined}
            onDrop={
                onMoveHere
                    ? (e) => {
                          e.preventDefault();
                          setOver(false);
                          const id = draggedEntryId(e);
                          if (id) onMoveHere(id);
                      }
                    : undefined
            }
            className={cn(
                "min-w-0 flex-1 truncate rounded-md px-2 py-1 text-left text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                active ? "bg-accent font-medium text-accent-foreground" : "hover:bg-muted",
                // A custom background overrides bg-accent, so mark the active one with a ring.
                active && customBg && "ring-1 ring-inset ring-primary",
                over && "ring-2 ring-primary ring-offset-1 ring-offset-background",
            )}
        >
            {label}
        </button>
    );
}

function RailIcon({
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
            className="rounded p-1 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus-visible:opacity-100 group-hover:opacity-100"
        >
            {children}
        </button>
    );
}
