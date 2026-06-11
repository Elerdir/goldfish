import { useEffect, useState } from "react";
import { Fingerprint } from "lucide-react";
import { useTranslation } from "react-i18next";

import { PasswordInput } from "@/components/PasswordInput";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { asCommandError, listBackups, restoreBackup, type BackupInfo } from "@/lib/tauri";
import { useVault } from "@/providers/VaultProvider";

const MIN_LENGTH = 8;

type Mode = "password" | "recovery" | "restore";

/** Formats a byte count as a compact KB/MB string. */
function formatSize(bytes: number): string {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export function UnlockScreen() {
    const { t } = useTranslation();
    const { unlock, unlockBiometric, unlockWithRecovery, biometricEnabled, busy, errorKey } =
        useVault();
    const [mode, setMode] = useState<Mode>("password");
    const [password, setPassword] = useState("");
    const [code, setCode] = useState("");
    const [newPw, setNewPw] = useState("");
    const [confirm, setConfirm] = useState("");

    // Restore-from-backup state.
    const [backups, setBackups] = useState<BackupInfo[] | null>(null);
    const [restoreBusy, setRestoreBusy] = useState(false);
    const [restoreMsg, setRestoreMsg] = useState<string | null>(null);
    const [restoreErr, setRestoreErr] = useState<string | null>(null);
    const [confirmName, setConfirmName] = useState<string | null>(null);

    const submit = () => {
        if (password.length > 0 && !busy) void unlock(password);
    };

    const recoveryReady =
        code.trim().length > 0 && newPw.length >= MIN_LENGTH && newPw === confirm && !busy;
    const submitRecovery = () => {
        if (recoveryReady) void unlockWithRecovery(code, newPw);
    };

    const loadBackups = () => {
        setBackups(null);
        setRestoreErr(null);
        listBackups()
            .then(setBackups)
            .catch((e) => {
                setBackups([]);
                setRestoreErr(t(`errors.${asCommandError(e).kind}`));
            });
    };

    useEffect(() => {
        if (mode === "restore") loadBackups();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [mode]);

    const doRestore = async (fileName: string) => {
        setRestoreBusy(true);
        setRestoreErr(null);
        setRestoreMsg(null);
        try {
            await restoreBackup(fileName);
            setConfirmName(null);
            setRestoreMsg(t("restore.done"));
            loadBackups(); // refresh (now includes the pre-restore snapshot)
        } catch (e) {
            setRestoreErr(t(`errors.${asCommandError(e).kind}`));
        } finally {
            setRestoreBusy(false);
        }
    };

    return (
        <Card className="w-full max-w-md">
            <CardHeader>
                <CardTitle>{t("unlock.title")}</CardTitle>
                <CardDescription>
                    {mode === "password"
                        ? t("unlock.subtitle")
                        : mode === "recovery"
                          ? t("recovery.unlock_subtitle")
                          : t("restore.subtitle")}
                </CardDescription>
            </CardHeader>

            {mode === "password" && (
                <>
                    <CardContent>
                        <div className="flex flex-col gap-2">
                            <Label htmlFor="unlock-password">{t("unlock.password")}</Label>
                            <PasswordInput
                                id="unlock-password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                onKeyDown={(e) => {
                                    if (e.key === "Enter") submit();
                                }}
                                autoComplete="current-password"
                                autoFocus
                            />
                        </div>
                        {errorKey && <p className="text-sm text-destructive">{t(errorKey)}</p>}
                    </CardContent>
                    <CardFooter className="flex-col gap-2">
                        <Button
                            className="w-full"
                            disabled={password.length === 0 || busy}
                            onClick={submit}
                        >
                            {busy ? t("unlock.unlocking") : t("unlock.unlock")}
                        </Button>
                        {biometricEnabled && (
                            <Button
                                variant="outline"
                                className="w-full"
                                disabled={busy}
                                onClick={() => void unlockBiometric()}
                            >
                                <Fingerprint size={16} />
                                {t("unlock.biometric")}
                            </Button>
                        )}
                        <div className="flex w-full justify-between">
                            <button
                                type="button"
                                className="text-xs text-muted-foreground underline-offset-2 hover:underline"
                                onClick={() => setMode("recovery")}
                            >
                                {t("recovery.use_code")}
                            </button>
                            <button
                                type="button"
                                className="text-xs text-muted-foreground underline-offset-2 hover:underline"
                                onClick={() => setMode("restore")}
                            >
                                {t("restore.use")}
                            </button>
                        </div>
                    </CardFooter>
                </>
            )}

            {mode === "recovery" && (
                <>
                    <CardContent>
                        <div className="flex flex-col gap-3">
                            <div className="flex flex-col gap-2">
                                <Label htmlFor="recovery-code">{t("recovery.code_label")}</Label>
                                <Input
                                    id="recovery-code"
                                    value={code}
                                    onChange={(e) => setCode(e.target.value)}
                                    autoComplete="off"
                                    spellCheck={false}
                                    className="font-mono"
                                    autoFocus
                                />
                            </div>
                            <div className="flex flex-col gap-2">
                                <Label htmlFor="recovery-newpw">{t("recovery.new_password")}</Label>
                                <PasswordInput
                                    id="recovery-newpw"
                                    value={newPw}
                                    onChange={(e) => setNewPw(e.target.value)}
                                    autoComplete="new-password"
                                />
                            </div>
                            <div className="flex flex-col gap-2">
                                <Label htmlFor="recovery-confirm">{t("onboarding.confirm")}</Label>
                                <PasswordInput
                                    id="recovery-confirm"
                                    value={confirm}
                                    onChange={(e) => setConfirm(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === "Enter") submitRecovery();
                                    }}
                                    autoComplete="new-password"
                                />
                            </div>
                            {newPw.length > 0 && newPw.length < MIN_LENGTH && (
                                <p className="text-xs text-destructive">
                                    {t("onboarding.too_short", { min: MIN_LENGTH })}
                                </p>
                            )}
                            {confirm.length > 0 && newPw !== confirm && (
                                <p className="text-xs text-destructive">{t("onboarding.mismatch")}</p>
                            )}
                            {errorKey && <p className="text-sm text-destructive">{t(errorKey)}</p>}
                        </div>
                    </CardContent>
                    <CardFooter className="flex-col gap-2">
                        <Button className="w-full" disabled={!recoveryReady} onClick={submitRecovery}>
                            {busy ? t("unlock.unlocking") : t("recovery.recover")}
                        </Button>
                        <button
                            type="button"
                            className="text-xs text-muted-foreground underline-offset-2 hover:underline"
                            onClick={() => setMode("password")}
                        >
                            {t("recovery.back")}
                        </button>
                    </CardFooter>
                </>
            )}

            {mode === "restore" && (
                <>
                    <CardContent>
                        <div className="flex flex-col gap-3">
                            {restoreMsg && (
                                <p className="text-sm text-green-600 dark:text-green-400">
                                    {restoreMsg}
                                </p>
                            )}
                            {restoreErr && <p className="text-sm text-destructive">{restoreErr}</p>}
                            {backups === null ? (
                                <p className="text-sm text-muted-foreground">{t("restore.loading")}</p>
                            ) : backups.length === 0 ? (
                                <p className="text-sm text-muted-foreground">{t("restore.empty")}</p>
                            ) : (
                                <ul className="flex max-h-64 flex-col gap-2 overflow-y-auto">
                                    {backups.map((b) => (
                                        <li
                                            key={b.fileName}
                                            className="flex items-center justify-between gap-2 rounded-md border border-border p-2"
                                        >
                                            <div className="min-w-0">
                                                <p className="truncate text-sm">
                                                    {new Date(b.createdAtMs).toLocaleString()}
                                                </p>
                                                <p className="text-xs text-muted-foreground">
                                                    {formatSize(b.sizeBytes)}
                                                    {b.fileName.includes("prerestore")
                                                        ? ` · ${t("restore.prerestore")}`
                                                        : ""}
                                                </p>
                                            </div>
                                            {confirmName === b.fileName ? (
                                                <div className="flex shrink-0 gap-1">
                                                    <Button
                                                        variant="destructive"
                                                        disabled={restoreBusy}
                                                        onClick={() => void doRestore(b.fileName)}
                                                    >
                                                        {t("restore.confirm")}
                                                    </Button>
                                                    <Button
                                                        variant="outline"
                                                        disabled={restoreBusy}
                                                        onClick={() => setConfirmName(null)}
                                                    >
                                                        {t("restore.cancel")}
                                                    </Button>
                                                </div>
                                            ) : (
                                                <Button
                                                    variant="outline"
                                                    className="shrink-0"
                                                    disabled={restoreBusy}
                                                    onClick={() => {
                                                        setRestoreMsg(null);
                                                        setConfirmName(b.fileName);
                                                    }}
                                                >
                                                    {t("restore.button")}
                                                </Button>
                                            )}
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    </CardContent>
                    <CardFooter className="flex-col gap-2">
                        <button
                            type="button"
                            className="text-xs text-muted-foreground underline-offset-2 hover:underline"
                            onClick={() => {
                                setMode("password");
                                setConfirmName(null);
                                setRestoreMsg(null);
                                setRestoreErr(null);
                            }}
                        >
                            {t("recovery.back")}
                        </button>
                    </CardFooter>
                </>
            )}
        </Card>
    );
}
