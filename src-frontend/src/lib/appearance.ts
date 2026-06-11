/** Helpers for applying a view's {@link Appearance} as inline CSS. */

import type { CSSProperties } from "react";

import type { Appearance } from "@/lib/tauri";

/**
 * Inline text style derived from an appearance, used for the entry list and the
 * editor preview. Unset overrides fall through to the inherited theme.
 */
export function appearanceTextStyle(a: Appearance): CSSProperties {
    return {
        color: a.textColor ?? undefined,
        fontWeight: a.bold ? 700 : undefined,
        fontStyle: a.italic ? "italic" : undefined,
        fontSize: a.fontSize ? `${a.fontSize}px` : undefined,
    };
}
