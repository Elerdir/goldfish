import { getCurrentWindow } from "@tauri-apps/api/window";

import { SettingsDialog } from "@/components/SettingsDialog";
import { useActivityPing } from "@/hooks/useActivityPing";
import { useExcludeFromCapture } from "@/hooks/useExcludeFromCapture";
import { emitVaultChanged } from "@/lib/tauri";

/**
 * Hosts the settings panel in its own OS window (`?view=settings`). Theme,
 * language and settings sync back to the main window via shared localStorage
 * (`storage` events); import/backup may have changed vault data, so closing the
 * window also notifies the main window to refresh its lists.
 */
export function SettingsWindow() {
    useExcludeFromCapture();
    useActivityPing();
    const close = () => {
        void emitVaultChanged();
        void getCurrentWindow().close();
    };
    return <SettingsDialog open fullWindow onClose={close} />;
}
