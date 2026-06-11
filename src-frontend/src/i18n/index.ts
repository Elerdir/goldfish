import i18next from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import de from "./locales/de.json";
import cs from "./locales/cs.json";

export const i18n = i18next;

export async function initI18n(): Promise<void> {
    await i18next
        .use(LanguageDetector)
        .use(initReactI18next)
        .init({
            resources: {
                en: { translation: en },
                de: { translation: de },
                cs: { translation: cs },
            },
            fallbackLng: "en",
            supportedLngs: ["en", "de", "cs"],
            interpolation: { escapeValue: false },
            detection: {
                order: ["localStorage", "navigator"],
                lookupLocalStorage: "goldfish-lng",
                caches: ["localStorage"],
            },
        });
}

export const SUPPORTED_LANGUAGES = ["en", "de", "cs"] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];
