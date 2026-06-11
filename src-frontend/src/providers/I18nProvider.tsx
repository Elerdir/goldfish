import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";

import { i18n, initI18n } from "@/i18n";

interface I18nProviderProps {
    children: ReactNode;
}

export function I18nProvider({ children }: I18nProviderProps) {
    const [ready, setReady] = useState(i18n.isInitialized);

    useEffect(() => {
        if (i18n.isInitialized) return;
        void initI18n().then(() => setReady(true));
    }, []);

    // Live-sync the language across windows (the Settings window persists it to
    // localStorage under `goldfish-lng`).
    useEffect(() => {
        const onStorage = (e: StorageEvent) => {
            if (e.key === "goldfish-lng" && e.newValue && e.newValue !== i18n.resolvedLanguage) {
                void i18n.changeLanguage(e.newValue);
            }
        };
        window.addEventListener("storage", onStorage);
        return () => window.removeEventListener("storage", onStorage);
    }, []);

    if (!ready) return null;
    return <I18nextProvider i18n={i18n}>{children}</I18nextProvider>;
}
