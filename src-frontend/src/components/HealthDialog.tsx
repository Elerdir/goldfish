import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { useSettings } from "@/providers/SettingsProvider";
import {
    vaultBreachScan,
    vaultHealth,
    type BreachItem,
    type HealthItem,
    type ReusedGroup,
} from "@/lib/tauri";

/**
 * Vault-health report: weak / reused / stale passwords and entries without 2FA.
 * Clicking any finding opens that entry's detail. The report is fetched fresh and
 * never cached (`gcTime: 0`) since it is derived from decrypted entries.
 */
export function HealthDialog({
    open,
    onClose,
    onSelect,
}: {
    open: boolean;
    onClose: () => void;
    onSelect: (id: string) => void;
}) {
    const { t } = useTranslation();
    const { settings } = useSettings();
    // If the user set a password-expiry reminder, the "stale" window follows it.
    const staleDays = settings.passwordExpiryDays > 0 ? settings.passwordExpiryDays : undefined;
    const query = useQuery({
        queryKey: ["vault-health", staleDays ?? 365],
        queryFn: () => vaultHealth(staleDays),
        enabled: open,
        gcTime: 0,
        staleTime: 0,
    });
    const report = query.data;
    const clean =
        report &&
        report.weak.length === 0 &&
        report.reused.length === 0 &&
        report.stale.length === 0 &&
        report.withoutTotp.length === 0;

    return (
        <Dialog
            open={open}
            onClose={onClose}
            title={t("health.title")}
            footer={<Button onClick={onClose}>{t("settings.close")}</Button>}
        >
            {query.isLoading && <p className="text-sm text-muted-foreground">{t("health.scanning")}</p>}
            {query.isError && <p className="text-sm text-destructive">{t("errors.generic")}</p>}
            {report && (
                <div className="flex flex-col gap-4">
                    <p className="text-xs text-muted-foreground">
                        {t("health.summary", { total: report.total })}
                    </p>
                    {clean ? (
                        <p className="flex items-center gap-1.5 text-sm text-green-600 dark:text-green-400">
                            <ShieldCheck size={16} />
                            {t("health.all_good")}
                        </p>
                    ) : (
                        <>
                            <Section title={t("health.weak")} items={report.weak} onSelect={onSelect} />
                            <ReusedSection groups={report.reused} onSelect={onSelect} />
                            <Section title={t("health.stale")} items={report.stale} onSelect={onSelect} />
                            <Section
                                title={t("health.no_totp")}
                                items={report.withoutTotp}
                                onSelect={onSelect}
                            />
                        </>
                    )}
                    <BreachScanSection open={open} onSelect={onSelect} />
                </div>
            )}
        </Dialog>
    );
}

/**
 * On-demand vault-wide breach scan. Not run automatically (it makes one network
 * request per unique password); the user starts it with a button.
 */
function BreachScanSection({ open, onSelect }: { open: boolean; onSelect: (id: string) => void }) {
    const { t } = useTranslation();
    const [scan, setScan] = useState(false);

    const query = useQuery({
        queryKey: ["vault-breach-scan"],
        queryFn: vaultBreachScan,
        enabled: open && scan,
        gcTime: 0,
        staleTime: 0,
    });

    // Reset when the dialog closes so reopening doesn't re-trigger the scan.
    useEffect(() => {
        if (!open) setScan(false);
    }, [open]);

    return (
        <section className="flex flex-col gap-1.5 border-t border-border pt-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t("health.breach_title")}
            </h3>
            {!scan && (
                <Button variant="outline" className="self-start" onClick={() => setScan(true)}>
                    <ShieldQuestion size={16} />
                    {t("health.breach_button")}
                </Button>
            )}
            {scan && query.isLoading && (
                <p className="text-sm text-muted-foreground">{t("health.breach_scanning")}</p>
            )}
            {scan && query.isError && <p className="text-sm text-destructive">{t("errors.network")}</p>}
            {query.isSuccess && query.data.length === 0 && (
                <p className="flex items-center gap-1.5 text-sm text-green-600 dark:text-green-400">
                    <ShieldCheck size={16} />
                    {t("health.breach_clean")}
                </p>
            )}
            {query.isSuccess && query.data.length > 0 && (
                <ul className="flex flex-col gap-1">
                    {query.data.map((item: BreachItem) => (
                        <li key={item.id}>
                            <BreachButton item={item} onClick={() => onSelect(item.id)} />
                        </li>
                    ))}
                </ul>
            )}
        </section>
    );
}

function BreachButton({ item, onClick }: { item: BreachItem; onClick: () => void }) {
    const { t } = useTranslation();
    return (
        <button
            type="button"
            onClick={onClick}
            className="flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-left text-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
            <span className="min-w-0 flex-1 truncate">{item.title}</span>
            <span className="flex shrink-0 items-center gap-1 text-xs font-medium text-destructive">
                <ShieldAlert size={13} />
                {t("entry.breach_pwned", { count: item.count })}
            </span>
        </button>
    );
}

function Section({
    title,
    items,
    onSelect,
}: {
    title: string;
    items: HealthItem[];
    onSelect: (id: string) => void;
}) {
    if (items.length === 0) return null;
    return (
        <section className="flex flex-col gap-1.5">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <ShieldAlert size={14} className="text-destructive" />
                {title} ({items.length})
            </h3>
            <ul className="flex flex-col gap-1">
                {items.map((i) => (
                    <li key={i.id}>
                        <FindingButton title={i.title} onClick={() => onSelect(i.id)} />
                    </li>
                ))}
            </ul>
        </section>
    );
}

function ReusedSection({
    groups,
    onSelect,
}: {
    groups: ReusedGroup[];
    onSelect: (id: string) => void;
}) {
    const { t } = useTranslation();
    if (groups.length === 0) return null;
    return (
        <section className="flex flex-col gap-1.5">
            <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <ShieldAlert size={14} className="text-destructive" />
                {t("health.reused")} ({groups.length})
            </h3>
            {groups.map((g) => (
                <div key={g.entries[0]?.id ?? g.count} className="rounded border border-border p-2">
                    <p className="mb-1 text-xs text-muted-foreground">
                        {t("health.reused_group", { count: g.count })}
                    </p>
                    <ul className="flex flex-col gap-1">
                        {g.entries.map((e) => (
                            <li key={e.id}>
                                <FindingButton title={e.title} onClick={() => onSelect(e.id)} />
                            </li>
                        ))}
                    </ul>
                </div>
            ))}
        </section>
    );
}

function FindingButton({ title, onClick }: { title: string; onClick: () => void }) {
    return (
        <button
            type="button"
            onClick={onClick}
            className="w-full truncate rounded px-2 py-1 text-left text-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
            {title}
        </button>
    );
}
