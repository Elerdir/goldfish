import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { useTranslation } from "react-i18next";

import { BackupSection } from "@/components/BackupSection";
import { RecoverySection } from "@/components/RecoverySection";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SUPPORTED_LANGUAGES, type SupportedLanguage } from "@/i18n";
import { useSettings } from "@/providers/SettingsProvider";
import { useTheme, type Theme } from "@/providers/ThemeProvider";
import { useVault } from "@/providers/VaultProvider";
import {
    appVersion,
    asCommandError,
    biometricAvailable,
    disableBiometric,
    enableBiometric,
    importFile,
    openLogsWindow,
    type ImportFormat,
} from "@/lib/tauri";
import { cn } from "@/lib/utils";

const THEMES: Theme[] = ["light", "dark", "system"];

const IMPORTERS: { format: ImportFormat; label: string; extensions: string[] }[] = [
    { format: "bitwarden", label: "Bitwarden", extensions: ["json"] },
    { format: "keepassxc", label: "KeePassXC", extensions: ["csv"] },
    { format: "onepassword", label: "1Password", extensions: ["csv"] },
];

export function SettingsDialog({
    open,
    onClose,
    fullWindow,
}: {
    open: boolean;
    onClose: () => void;
    fullWindow?: boolean;
}) {
    const { t, i18n } = useTranslation();
    const { theme, setTheme } = useTheme();
    const { settings, update } = useSettings();
    const { status, biometricEnabled, refreshBiometric } = useVault();
    const qc = useQueryClient();

    const [bioAvailable, setBioAvailable] = useState(false);
    const [bioError, setBioError] = useState<string | null>(null);
    const [importMsg, setImportMsg] = useState<string | null>(null);
    const [importErr, setImportErr] = useState<string | null>(null);
    const [version, setVersion] = useState<string | null>(null);

    useEffect(() => {
        if (!open) return;
        void biometricAvailable()
            .then(setBioAvailable)
            .catch(() => setBioAvailable(false));
        void appVersion()
            .then(setVersion)
            .catch(() => setVersion(null));
    }, [open]);

    const toggleBiometric = async (enable: boolean) => {
        setBioError(null);
        try {
            if (enable) {
                await enableBiometric();
            } else {
                await disableBiometric();
            }
            await refreshBiometric();
        } catch (err) {
            setBioError(`errors.${asCommandError(err).kind}`);
        }
    };

    const runImport = async (format: ImportFormat, extensions: string[]) => {
        setImportMsg(null);
        setImportErr(null);
        try {
            const path = await openFileDialog({ multiple: false, filters: [{ name: format, extensions }] });
            if (typeof path !== "string") return;
            const count = await importFile(format, path);
            await qc.invalidateQueries({ queryKey: ["entries"] });
            setImportMsg(t("settings.import_done", { count }));
        } catch (err) {
            setImportErr(`errors.${asCommandError(err).kind}`);
        }
    };

    return (
        <Dialog
            open={open}
            onClose={onClose}
            fullWindow={fullWindow}
            title={t("settings.title")}
            footer={<Button onClick={onClose}>{t("settings.close")}</Button>}
        >
            <div className="flex flex-col gap-6">
                <section className="flex flex-col gap-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        {t("settings.appearance")}
                    </h3>

                    <div className="flex items-center justify-between gap-3">
                        <Label>{t("theme.label")}</Label>
                        <div className="flex gap-1">
                            {THEMES.map((option) => (
                                <SegBtn
                                    key={option}
                                    active={theme === option}
                                    onClick={() => setTheme(option)}
                                >
                                    {t(`theme.${option}`)}
                                </SegBtn>
                            ))}
                        </div>
                    </div>

                    <div className="flex items-center justify-between gap-3">
                        <Label>{t("language.label")}</Label>
                        <div className="flex gap-1">
                            {SUPPORTED_LANGUAGES.map((lng) => (
                                <SegBtn
                                    key={lng}
                                    active={(i18n.resolvedLanguage as SupportedLanguage) === lng}
                                    onClick={() => void i18n.changeLanguage(lng)}
                                >
                                    {lng.toUpperCase()}
                                </SegBtn>
                            ))}
                        </div>
                    </div>
                </section>

                <section className="flex flex-col gap-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        {t("settings.behavior")}
                    </h3>

                    <div className="flex flex-col gap-1.5">
                        <Label htmlFor="autolock">{t("settings.autolock")}</Label>
                        <div className="flex items-center gap-2">
                            <Input
                                id="autolock"
                                type="number"
                                min={0}
                                max={240}
                                value={settings.autoLockMinutes}
                                onChange={(e) =>
                                    update({ autoLockMinutes: Number(e.target.value) })
                                }
                                className="w-24"
                            />
                            <span className="text-sm text-muted-foreground">
                                {t("settings.minutes")}
                            </span>
                        </div>
                        <p className="text-xs text-muted-foreground">{t("settings.autolock_help")}</p>
                    </div>

                    <label className="flex items-center gap-2 text-sm">
                        <input
                            type="checkbox"
                            checked={settings.lockOnBlur}
                            onChange={(e) => update({ lockOnBlur: e.target.checked })}
                            className="h-4 w-4 accent-primary"
                        />
                        {t("settings.lock_on_blur")}
                    </label>

                    <div className="flex flex-col gap-1.5">
                        <Label htmlFor="clipboard">{t("settings.clipboard_clear")}</Label>
                        <div className="flex items-center gap-2">
                            <Input
                                id="clipboard"
                                type="number"
                                min={5}
                                max={300}
                                value={settings.clipboardClearSeconds}
                                onChange={(e) =>
                                    update({ clipboardClearSeconds: Number(e.target.value) })
                                }
                                className="w-24"
                            />
                            <span className="text-sm text-muted-foreground">
                                {t("settings.seconds")}
                            </span>
                        </div>
                    </div>

                    <div className="flex flex-col gap-1.5">
                        <Label htmlFor="expiry">{t("settings.password_expiry")}</Label>
                        <div className="flex items-center gap-2">
                            <Input
                                id="expiry"
                                type="number"
                                min={0}
                                max={3650}
                                value={settings.passwordExpiryDays}
                                onChange={(e) =>
                                    update({ passwordExpiryDays: Number(e.target.value) })
                                }
                                className="w-24"
                            />
                            <span className="text-sm text-muted-foreground">{t("settings.days")}</span>
                        </div>
                        <p className="text-xs text-muted-foreground">
                            {t("settings.password_expiry_help")}
                        </p>
                    </div>

                    <div className="flex flex-col gap-1.5">
                        <label className="flex items-center gap-2 text-sm">
                            <input
                                type="checkbox"
                                checked={biometricEnabled}
                                disabled={
                                    !bioAvailable || (!biometricEnabled && status !== "unlocked")
                                }
                                onChange={(e) => void toggleBiometric(e.target.checked)}
                                className="h-4 w-4 accent-primary"
                            />
                            {t("settings.biometric")}
                        </label>
                        {!bioAvailable && (
                            <p className="text-xs text-muted-foreground">
                                {t("settings.biometric_unavailable_hint")}
                            </p>
                        )}
                        {bioAvailable && !biometricEnabled && status !== "unlocked" && (
                            <p className="text-xs text-muted-foreground">
                                {t("settings.biometric_locked_hint")}
                            </p>
                        )}
                        {bioError && <p className="text-xs text-destructive">{t(bioError)}</p>}
                    </div>
                </section>

                {status === "unlocked" && (
                    <section className="flex flex-col gap-3">
                        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                            {t("settings.import")}
                        </h3>
                        <p className="text-xs text-muted-foreground">{t("settings.import_help")}</p>
                        <div className="flex flex-wrap gap-2">
                            {IMPORTERS.map(({ format, label, extensions }) => (
                                <Button
                                    key={format}
                                    variant="outline"
                                    onClick={() => void runImport(format, extensions)}
                                >
                                    {label}
                                </Button>
                            ))}
                        </div>
                        {importMsg && <p className="text-xs text-green-600 dark:text-green-400">{importMsg}</p>}
                        {importErr && <p className="text-xs text-destructive">{t(importErr)}</p>}
                    </section>
                )}

                {status === "unlocked" && <BackupSection />}
                {status === "unlocked" && <RecoverySection />}

                <section className="flex flex-col gap-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        {t("logs.diagnostics")}
                    </h3>
                    <Button
                        variant="outline"
                        className="self-start"
                        onClick={() => void openLogsWindow()}
                    >
                        {t("logs.view")}
                    </Button>
                </section>

                {version && (
                    <p className="border-t border-border pt-3 text-center text-xs text-muted-foreground">
                        Goldfish v{version}
                    </p>
                )}
            </div>
        </Dialog>
    );
}

function SegBtn({
    active,
    onClick,
    children,
}: {
    active: boolean;
    onClick: () => void;
    children: React.ReactNode;
}) {
    return (
        <button
            type="button"
            onClick={onClick}
            className={cn(
                "rounded-md border border-border px-2.5 py-1 text-xs font-medium transition-colors",
                active
                    ? "bg-primary text-primary-foreground"
                    : "bg-background hover:bg-accent hover:text-accent-foreground",
            )}
        >
            {children}
        </button>
    );
}
