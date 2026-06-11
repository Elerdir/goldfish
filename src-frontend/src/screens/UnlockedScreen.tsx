import { Lock } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useVault } from "@/providers/VaultProvider";

/**
 * Placeholder shown once the vault is unlocked. Phase 5 replaces this with the
 * entry list / detail UI.
 */
export function UnlockedScreen() {
    const { t } = useTranslation();
    const { lock, busy } = useVault();

    return (
        <Card className="w-full max-w-lg">
            <CardHeader>
                <CardTitle>{t("unlocked.title")}</CardTitle>
                <CardDescription>{t("unlocked.subtitle")}</CardDescription>
            </CardHeader>
            <CardContent>
                <Button variant="outline" onClick={() => void lock()} disabled={busy}>
                    <Lock size={16} />
                    {t("unlocked.lock")}
                </Button>
            </CardContent>
        </Card>
    );
}
