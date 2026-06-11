import { useState } from "react";
import { useTranslation } from "react-i18next";

import { PasswordInput } from "@/components/PasswordInput";
import { PasswordStrength } from "@/components/PasswordStrength";
import { Button } from "@/components/ui/button";
import {
    Card,
    CardContent,
    CardDescription,
    CardFooter,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { useVault } from "@/providers/VaultProvider";

const MIN_LENGTH = 8;
/** Minimum zxcvbn score (0–4) required for the master password ("good"). */
const MIN_SCORE = 3;

export function OnboardingScreen() {
    const { t } = useTranslation();
    const { createVault, busy, errorKey } = useVault();
    const [password, setPassword] = useState("");
    const [confirm, setConfirm] = useState("");
    const [score, setScore] = useState(0);

    const tooShort = password.length > 0 && password.length < MIN_LENGTH;
    const tooWeak = password.length >= MIN_LENGTH && score < MIN_SCORE;
    const mismatch = confirm.length > 0 && password !== confirm;
    const canSubmit =
        password.length >= MIN_LENGTH && score >= MIN_SCORE && password === confirm && !busy;

    const submit = () => {
        if (canSubmit) void createVault(password);
    };

    return (
        <Card className="w-full max-w-md">
            <CardHeader>
                <CardTitle>{t("onboarding.title")}</CardTitle>
                <CardDescription>{t("onboarding.subtitle")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div className="flex flex-col gap-2">
                    <Label htmlFor="master-password">{t("onboarding.password")}</Label>
                    <PasswordInput
                        id="master-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="new-password"
                        autoFocus
                    />
                    <PasswordStrength password={password} onScore={setScore} />
                    {tooShort && (
                        <p className="text-xs text-destructive">
                            {t("onboarding.too_short", { min: MIN_LENGTH })}
                        </p>
                    )}
                    {tooWeak && (
                        <p className="text-xs text-destructive">{t("onboarding.too_weak")}</p>
                    )}
                </div>

                <div className="flex flex-col gap-2">
                    <Label htmlFor="confirm-password">{t("onboarding.confirm")}</Label>
                    <PasswordInput
                        id="confirm-password"
                        value={confirm}
                        onChange={(e) => setConfirm(e.target.value)}
                        onKeyDown={(e) => {
                            if (e.key === "Enter") submit();
                        }}
                        autoComplete="new-password"
                    />
                    {mismatch && (
                        <p className="text-xs text-destructive">{t("onboarding.mismatch")}</p>
                    )}
                </div>

                <p className="rounded-md bg-muted p-3 text-xs text-muted-foreground">
                    {t("onboarding.warning")}
                </p>

                {errorKey && <p className="text-sm text-destructive">{t(errorKey)}</p>}
            </CardContent>
            <CardFooter>
                <Button className="w-full" disabled={!canSubmit} onClick={submit}>
                    {busy ? t("onboarding.creating") : t("onboarding.create")}
                </Button>
            </CardFooter>
        </Card>
    );
}
