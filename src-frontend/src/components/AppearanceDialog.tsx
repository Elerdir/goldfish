import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { appearanceTextStyle } from "@/lib/appearance";
import { EMPTY_APPEARANCE, type Appearance } from "@/lib/tauri";

const DEFAULT_BG = "#334155";
const DEFAULT_FG = "#f1f5f9";
const DEFAULT_SIZE = 14;
const MIN_FONT = 10;
const MAX_FONT = 28;

/**
 * Edits a single view's {@link Appearance}: background + text color (each
 * toggleable), bold, italic, and font size. The font *family* is not editable —
 * it is shared app-wide. The caller persists the result (folder → vault,
 * "all entries" → settings).
 */
export function AppearanceDialog({
    open,
    title,
    value,
    onClose,
    onSave,
}: {
    open: boolean;
    title: string;
    value: Appearance;
    onClose: () => void;
    onSave: (appearance: Appearance) => void;
}) {
    const { t } = useTranslation();
    const [draft, setDraft] = useState<Appearance>(value);

    // Re-sync whenever the dialog opens (it is reused for different views).
    useEffect(() => {
        if (open) setDraft(value);
    }, [open, value]);

    const set = (partial: Partial<Appearance>) => setDraft((d) => ({ ...d, ...partial }));

    return (
        <Dialog
            open={open}
            onClose={onClose}
            title={title}
            footer={
                <div className="flex w-full items-center justify-between">
                    <Button variant="ghost" onClick={() => setDraft(EMPTY_APPEARANCE)}>
                        {t("appearance.reset")}
                    </Button>
                    <div className="flex gap-2">
                        <Button variant="outline" onClick={onClose}>
                            {t("entry.cancel")}
                        </Button>
                        <Button onClick={() => onSave(draft)}>{t("entry.save")}</Button>
                    </div>
                </div>
            }
        >
            <div className="flex flex-col gap-4">
                <div
                    className="flex items-center justify-center rounded-lg border border-border px-3 py-6"
                    style={{ background: draft.background ?? undefined }}
                >
                    <span style={appearanceTextStyle(draft)}>{t("appearance.preview")}</span>
                </div>

                <ColorRow
                    label={t("appearance.background")}
                    value={draft.background}
                    fallback={DEFAULT_BG}
                    onChange={(v) => set({ background: v })}
                />
                <ColorRow
                    label={t("appearance.text_color")}
                    value={draft.textColor}
                    fallback={DEFAULT_FG}
                    onChange={(v) => set({ textColor: v })}
                />

                <label className="flex items-center gap-2 text-sm">
                    <input
                        type="checkbox"
                        checked={draft.bold}
                        onChange={(e) => set({ bold: e.target.checked })}
                        className="h-4 w-4 accent-primary"
                    />
                    {t("appearance.bold")}
                </label>
                <label className="flex items-center gap-2 text-sm">
                    <input
                        type="checkbox"
                        checked={draft.italic}
                        onChange={(e) => set({ italic: e.target.checked })}
                        className="h-4 w-4 accent-primary"
                    />
                    {t("appearance.italic")}
                </label>

                <div className="flex flex-col gap-1.5">
                    <label className="flex items-center gap-2 text-sm">
                        <input
                            type="checkbox"
                            checked={draft.fontSize !== null}
                            onChange={(e) => set({ fontSize: e.target.checked ? DEFAULT_SIZE : null })}
                            className="h-4 w-4 accent-primary"
                        />
                        {t("appearance.font_size")}
                    </label>
                    {draft.fontSize !== null && (
                        <div className="flex items-center gap-2 pl-6">
                            <input
                                type="range"
                                min={MIN_FONT}
                                max={MAX_FONT}
                                value={draft.fontSize}
                                onChange={(e) => set({ fontSize: Number(e.target.value) })}
                                className="flex-1 accent-primary"
                            />
                            <span className="w-12 text-right text-sm tabular-nums">
                                {draft.fontSize}px
                            </span>
                        </div>
                    )}
                </div>
            </div>
        </Dialog>
    );
}

function ColorRow({
    label,
    value,
    fallback,
    onChange,
}: {
    label: string;
    value: string | null;
    fallback: string;
    onChange: (value: string | null) => void;
}) {
    return (
        <div className="flex items-center justify-between gap-3">
            <label className="flex items-center gap-2 text-sm">
                <input
                    type="checkbox"
                    checked={value !== null}
                    onChange={(e) => onChange(e.target.checked ? fallback : null)}
                    className="h-4 w-4 accent-primary"
                />
                {label}
            </label>
            {value !== null && (
                <input
                    type="color"
                    aria-label={label}
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    className="h-8 w-14 cursor-pointer rounded border border-border bg-transparent"
                />
            )}
        </div>
    );
}
