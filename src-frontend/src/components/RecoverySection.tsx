import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { asCommandError, disableRecovery, enableRecovery, recoveryEnabled } from "@/lib/tauri";

/**
 * Recovery-code management. Enabling generates a one-time code (shown once) that
 * can later reset the master password. It is a second path to the vault, so the
 * UI warns the user to store it safely.
 */
export function RecoverySection() {
    const { t } = useTranslation();
    const [enabled, setEnabled] = useState(false);
    const [code, setCode] = useState<string | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    useEffect(() => {
        void recoveryEnabled()
            .then(setEnabled)
            .catch(() => setEnabled(false));
    }, []);

    const enable = async () => {
        setErr(null);
        setBusy(true);
        try {
            setCode(await enableRecovery());
            setEnabled(true);
        } catch (e) {
            setErr(t(`errors.${asCommandError(e).kind}`));
        } finally {
            setBusy(false);
        }
    };

    const disable = async () => {
        setErr(null);
        setBusy(true);
        try {
            await disableRecovery();
            setEnabled(false);
            setCode(null);
        } catch (e) {
            setErr(t(`errors.${asCommandError(e).kind}`));
        } finally {
            setBusy(false);
        }
    };

    return (
        <section className="flex flex-col gap-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t("recovery.title")}
            </h3>
            <p className="text-xs text-muted-foreground">{t("recovery.help")}</p>

            {code && (
                <div className="flex flex-col gap-2 rounded-md border border-goldfish bg-muted p-3">
                    <p className="text-xs font-medium">{t("recovery.code_label")}</p>
                    <code className="select-all break-all font-mono text-sm">{code}</code>
                    <p className="text-xs text-destructive">{t("recovery.code_warning")}</p>
                </div>
            )}

            <div className="flex gap-2">
                {enabled ? (
                    <>
                        <Button variant="outline" disabled={busy} onClick={() => void enable()}>
                            {t("recovery.regenerate")}
                        </Button>
                        <Button variant="destructive" disabled={busy} onClick={() => void disable()}>
                            {t("recovery.disable")}
                        </Button>
                    </>
                ) : (
                    <Button variant="outline" disabled={busy} onClick={() => void enable()}>
                        {t("recovery.enable")}
                    </Button>
                )}
            </div>
            {err && <p className="text-xs text-destructive">{err}</p>}
        </section>
    );
}
