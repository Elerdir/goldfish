/**
 * Drag-and-drop wiring shared between the entry list and the folder rail.
 *
 * Entries are dragged with their id carried in the native {@link DataTransfer}
 * under a custom MIME type, so a drop target (another row, or a folder) can read
 * it without any shared React state. Reordering rewrites a view's order; a drop
 * onto a folder moves the entry.
 */

/** MIME key under which a dragged entry's id travels in the DataTransfer. */
export const ENTRY_MIME = "application/x-goldfish-entry";

/** Reads a dragged entry id from a drop event, or `null` if none is present. */
export function draggedEntryId(e: React.DragEvent): string | null {
    const id = e.dataTransfer.getData(ENTRY_MIME);
    return id === "" ? null : id;
}
