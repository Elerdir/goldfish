import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { estimateStrength } from "@/lib/strength";
import { cn } from "@/lib/utils";

const BAR_COLORS = [
    "bg-border",
    "bg-destructive",
    "bg-orange-500",
    "bg-yellow-500",
    "bg-green-500",
] as const;

const LABEL_KEYS = [
    "strength.none",
    "strength.weak",
    "strength.fair",
    "strength.good",
    "strength.strong",
] as const;

export function PasswordStrength({
    password,
    onScore,
}: {
    password: string;
    /** Called with the latest 0–4 score (e.g. to gate a submit button). */
    onScore?: (score: number) => void;
}) {
    const { t } = useTranslation();
    const [score, setScore] = useState(0);

    useEffect(() => {
        let cancelled = false;
        const handle = window.setTimeout(() => {
            void estimateStrength(password).then((s) => {
                if (!cancelled) {
                    setScore(s);
                    onScore?.(s);
                }
            });
        }, 120);
        return () => {
            cancelled = true;
            window.clearTimeout(handle);
        };
    }, [password, onScore]);

    const color = BAR_COLORS[score] ?? "bg-border";
    const labelKey = LABEL_KEYS[score] ?? "strength.none";

    return (
        <div className="flex flex-col gap-1.5" aria-live="polite">
            <div className="flex gap-1">
                {[1, 2, 3, 4].map((i) => (
                    <div
                        key={i}
                        className={cn(
                            "h-1.5 flex-1 rounded-full transition-colors",
                            i <= score ? color : "bg-border",
                        )}
                    />
                ))}
            </div>
            <span className="text-xs text-muted-foreground">
                {t("strength.label")}: {t(labelKey)}
            </span>
        </div>
    );
}
