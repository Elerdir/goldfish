import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { open as openFileDialog, save } from "@tauri-apps/plugin-dialog";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { PasswordInput } from "@/components/PasswordInput";
import { PasswordStrength } from "@/components/PasswordStrength";
import { asCommandError, exportVault, importVaultFile } from "@/lib/tauri";

/** Minimum length we require for an export password (independent of the vault). */
const MIN_EXPORT_PASSWORD = 8;
/** Minimum zxcvbn score (0–4) for an export password — a backup is a full,
 * portable copy of the vault, so a weak password here is the weakest link. */
const MIN_EXPORT_SCORE = 3;

const GOLDFISH_FILTER = [{ name: "Goldfish", extensions: ["goldfish"] }];

/**
 * Encrypted backup: export the whole vault to a password-protected `.goldfish`
 * file, or import entries from one. The export password is independent of the
 * master password, so a backup can be shared or restored elsewhere. All crypto
 * and file I/O happen in Rust — plaintext never crosses this boundary.
 */
export function BackupSection() {
    const { t } = useTranslation();
    const qc = useQueryClient();

    const [exportPw, setExportPw] = useState("");
    const [exportPw2, setExportPw2] = useState("");
    const [exportScore, setExportScore] = useState(0);
    const [importPw, setImportPw] = useState("");
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<string | null>(null);
    const [err, setErr] = useState<string | null>(null);

    const reset = () => {
        setMsg(null);
        setErr(null);
    };

    const runExport = async () => {
        reset();
        if (exportPw.length < MIN_EXPORT_PASSWORD) {
            setErr(t("backup.too_short", { min: MIN_EXPORT_PASSWORD }));
            return;
        }
        if (exportScore < MIN_EXPORT_SCORE) {
            setErr(t("backup.too_weak"));
            return;
        }
        if (exportPw !== exportPw2) {
            setErr(t("backup.mismatch"));
            return;
        }
        setBusy(true);
        try {
            const path = await save({
                defaultPath: "goldfish-backup.goldfish",
                filters: GOLDFISH_FILTER,
            });
            if (typeof path !== "string") return;
            const count = await exportVault(exportPw, path);
            setMsg(t("backup.export_done", { count }));
            setExportPw("");
            setExportPw2("");
        } catch (e) {
            setErr(t(`errors.${asCommandError(e).kind}`));
        } finally {
            setBusy(false);
        }
    };

    const runImport = async () => {
        reset();
        if (importPw.length === 0) {
            setErr(t("backup.password_required"));
            return;
        }
        setBusy(true);
        try {
            const path = await openFileDialog({ multiple: false, filters: GOLDFISH_FILTER });
            if (typeof path !== "string") return;
            const count = await importVaultFile(importPw, path);
            await qc.invalidateQueries({ queryKey: ["entries"] });
            setMsg(t("backup.import_done", { count }));
            setImportPw("");
        } catch (e) {
            setErr(t(`errors.${asCommandError(e).kind}`));
        } finally {
            setBusy(false);
        }
    };

    return (
        <section className="flex flex-col gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t("backup.title")}
            </h3>
            <p className="text-xs text-muted-foreground">{t("backup.help")}</p>

            <div className="flex flex-col gap-2">
                <Label htmlFor="export-pw">{t("backup.export_password")}</Label>
                <PasswordInput
                    id="export-pw"
                    value={exportPw}
                    onChange={(e) => setExportPw(e.target.value)}
                    autoComplete="new-password"
                    placeholder={t("backup.export_password")}
                />
                <PasswordInput
                    id="export-pw2"
                    value={exportPw2}
                    onChange={(e) => setExportPw2(e.target.value)}
                    autoComplete="new-password"
                    placeholder={t("backup.confirm_password")}
                />
                {exportPw.length > 0 && (
                    <PasswordStrength password={exportPw} onScore={setExportScore} />
                )}
                <Button variant="outline" disabled={busy} onClick={() => void runExport()}>
                    {t("backup.export_button")}
                </Button>
            </div>

            <div className="mt-1 flex flex-col gap-2 border-t border-border pt-3">
                <Label htmlFor="import-pw">{t("backup.import_password")}</Label>
                <PasswordInput
                    id="import-pw"
                    value={importPw}
                    onChange={(e) => setImportPw(e.target.value)}
                    autoComplete="current-password"
                    placeholder={t("backup.import_password")}
                />
                <Button variant="outline" disabled={busy} onClick={() => void runImport()}>
                    {t("backup.import_button")}
                </Button>
            </div>

            {msg && <p className="text-xs text-green-600 dark:text-green-400">{msg}</p>}
            {err && <p className="text-xs text-destructive">{err}</p>}
        </section>
    );
}
