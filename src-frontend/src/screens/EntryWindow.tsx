import { getCurrentWindow } from "@tauri-apps/api/window";

import { EntryFormDialog } from "@/components/EntryFormDialog";
import { useActivityPing } from "@/hooks/useActivityPing";
import { useExcludeFromCapture } from "@/hooks/useExcludeFromCapture";
import { emitVaultChanged } from "@/lib/tauri";

/**
 * Hosts the add/edit entry form in its own OS window (`?view=entry&id=…`). On
 * save it notifies the main window (so its lists refresh) and closes itself.
 */
export function EntryWindow({ entryId }: { entryId: string | null }) {
    useExcludeFromCapture();
    useActivityPing();
    const close = () => void getCurrentWindow().close();
    return (
        <EntryFormDialog
            open
            fullWindow
            entryId={entryId}
            onClose={close}
            onSaved={() => {
                void emitVaultChanged();
                close();
            }}
        />
    );
}
