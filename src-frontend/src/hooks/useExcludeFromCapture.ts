import { useEffect } from "react";

import { protectWindow } from "@/lib/tauri";

/**
 * Excludes the hosting window from screen capture / recording on mount (Windows
 * only, best-effort). Mount this in every standalone sub-window (settings, logs,
 * entry editor) so it carries the same protection as the main window — which is
 * excluded natively at startup.
 */
export function useExcludeFromCapture(): void {
    useEffect(() => {
        void protectWindow();
    }, []);
}
