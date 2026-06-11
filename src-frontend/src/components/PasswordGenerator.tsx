import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
    asCommandError,
    generatePassphrase,
    generatePassword,
    type GenPolicy,
    type PassphrasePolicy,
} from "@/lib/tauri";

const DEFAULT_POLICY: GenPolicy = {
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
};

const DEFAULT_PASSPHRASE: PassphrasePolicy = {
    words: 6,
    separator: "-",
    capitalize: false,
    includeNumber: false,
};

type ToggleKey = "lowercase" | "uppercase" | "digits" | "symbols" | "excludeAmbiguous";

const TOGGLES: { key: ToggleKey; labelKey: string }[] = [
    { key: "lowercase", labelKey: "generator.lowercase" },
    { key: "uppercase", labelKey: "generator.uppercase" },
    { key: "digits", labelKey: "generator.digits" },
    { key: "symbols", labelKey: "generator.symbols" },
    { key: "excludeAmbiguous", labelKey: "generator.exclude_ambiguous" },
];

type Mode = "chars" | "words";

export function PasswordGenerator({ onGenerate }: { onGenerate: (password: string) => void }) {
    const { t } = useTranslation();
    const [mode, setMode] = useState<Mode>("chars");
    const [policy, setPolicy] = useState<GenPolicy>(DEFAULT_POLICY);
    const [phrase, setPhrase] = useState<PassphrasePolicy>(DEFAULT_PASSPHRASE);
    const [busy, setBusy] = useState(false);
    const [errorKey, setErrorKey] = useState<string | null>(null);

    const noCharset =
        !policy.lowercase && !policy.uppercase && !policy.digits && !policy.symbols;
    const blocked = mode === "chars" && noCharset;

    const generate = async () => {
        if (blocked) return;
        setBusy(true);
        setErrorKey(null);
        try {
            const result =
                mode === "chars"
                    ? await generatePassword(policy)
                    : await generatePassphrase(phrase);
            onGenerate(result);
        } catch (err) {
            setErrorKey(`errors.${asCommandError(err).kind}`);
        } finally {
            setBusy(false);
        }
    };

    return (
        <div className="mt-2 flex flex-col gap-3 rounded-md border border-border bg-muted/40 p-3">
            <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-medium">{t("generator.title")}</span>
                <div className="flex gap-1">
                    <ModeBtn active={mode === "chars"} onClick={() => setMode("chars")}>
                        {t("generator.mode_password")}
                    </ModeBtn>
                    <ModeBtn active={mode === "words"} onClick={() => setMode("words")}>
                        {t("generator.mode_passphrase")}
                    </ModeBtn>
                </div>
            </div>

            {mode === "chars" ? (
                <>
                    <div className="flex items-center justify-end">
                        <span className="font-mono text-xs text-muted-foreground">
                            {t("generator.length")}: {policy.length}
                        </span>
                    </div>
                    <input
                        type="range"
                        min={8}
                        max={64}
                        value={policy.length}
                        onChange={(e) =>
                            setPolicy((p) => ({ ...p, length: Number(e.target.value) }))
                        }
                        className="w-full accent-primary"
                        aria-label={t("generator.length")}
                    />
                    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                        {TOGGLES.map(({ key, labelKey }) => (
                            <label key={key} className="flex items-center gap-1.5 text-sm">
                                <input
                                    type="checkbox"
                                    checked={policy[key]}
                                    onChange={(e) =>
                                        setPolicy((p) => ({ ...p, [key]: e.target.checked }))
                                    }
                                    className="h-4 w-4 accent-primary"
                                />
                                {t(labelKey)}
                            </label>
                        ))}
                    </div>
                </>
            ) : (
                <>
                    <div className="flex items-center justify-between gap-3">
                        <span className="font-mono text-xs text-muted-foreground">
                            {t("generator.words")}: {phrase.words}
                        </span>
                        <label className="flex items-center gap-1.5 text-sm">
                            {t("generator.separator")}
                            <input
                                type="text"
                                maxLength={1}
                                value={phrase.separator}
                                onChange={(e) =>
                                    setPhrase((p) => ({ ...p, separator: e.target.value }))
                                }
                                className="w-8 rounded border border-border bg-background px-1 py-0.5 text-center text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                                aria-label={t("generator.separator")}
                            />
                        </label>
                    </div>
                    <input
                        type="range"
                        min={3}
                        max={12}
                        value={phrase.words}
                        onChange={(e) =>
                            setPhrase((p) => ({ ...p, words: Number(e.target.value) }))
                        }
                        className="w-full accent-primary"
                        aria-label={t("generator.words")}
                    />
                    <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                        <label className="flex items-center gap-1.5 text-sm">
                            <input
                                type="checkbox"
                                checked={phrase.capitalize}
                                onChange={(e) =>
                                    setPhrase((p) => ({ ...p, capitalize: e.target.checked }))
                                }
                                className="h-4 w-4 accent-primary"
                            />
                            {t("generator.capitalize")}
                        </label>
                        <label className="flex items-center gap-1.5 text-sm">
                            <input
                                type="checkbox"
                                checked={phrase.includeNumber}
                                onChange={(e) =>
                                    setPhrase((p) => ({ ...p, includeNumber: e.target.checked }))
                                }
                                className="h-4 w-4 accent-primary"
                            />
                            {t("generator.include_number")}
                        </label>
                    </div>
                </>
            )}

            {errorKey && <p className="text-xs text-destructive">{t(errorKey)}</p>}

            <Button
                type="button"
                variant="outline"
                disabled={blocked || busy}
                onClick={() => void generate()}
                className="self-start"
            >
                <RefreshCw size={16} />
                {t("generator.generate")}
            </Button>
        </div>
    );
}

function ModeBtn({
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
                "rounded-md border border-border px-2 py-0.5 text-xs font-medium transition-colors",
                active
                    ? "bg-primary text-primary-foreground"
                    : "bg-background hover:bg-accent hover:text-accent-foreground",
            )}
        >
            {children}
        </button>
    );
}
