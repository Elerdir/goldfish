import { useEffect, useRef } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

interface DialogProps {
    open: boolean;
    onClose: () => void;
    title: string;
    children: ReactNode;
    footer?: ReactNode;
    /**
     * Render as a full-window panel (header + scrolling body + footer that fill
     * the viewport) instead of a centered modal. Used when the dialog is hosted
     * in its own OS window.
     */
    fullWindow?: boolean;
}

const FOCUSABLE =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Minimal accessible modal: overlay + centered panel, ESC and click-outside
 * close, with focus management — focus moves into the dialog on open, Tab is
 * trapped inside it, and focus is restored to the previously-focused element on
 * close (so keyboard and screen-reader users aren't dropped or lost).
 */
export function Dialog({ open, onClose, title, children, footer, fullWindow }: DialogProps) {
    const panelRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!open) return undefined;
        const previouslyFocused = document.activeElement as HTMLElement | null;

        const focusable = (): HTMLElement[] => {
            const panel = panelRef.current;
            if (!panel) return [];
            return Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
                (el) => el.offsetParent !== null,
            );
        };

        // Move focus into the dialog (first focusable, else the panel itself).
        (focusable()[0] ?? panelRef.current)?.focus();

        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") {
                onClose();
                return;
            }
            if (e.key !== "Tab") return;
            const items = focusable();
            const first = items[0];
            const last = items[items.length - 1];
            if (!first || !last) {
                // Nothing focusable — keep focus on the panel.
                e.preventDefault();
                panelRef.current?.focus();
                return;
            }
            const active = document.activeElement;
            if (e.shiftKey && active === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && active === last) {
                e.preventDefault();
                first.focus();
            }
        };

        window.addEventListener("keydown", onKey);
        return () => {
            window.removeEventListener("keydown", onKey);
            previouslyFocused?.focus?.();
        };
    }, [open, onClose]);

    if (!open) return null;

    if (fullWindow) {
        return (
            <div
                ref={panelRef}
                role="dialog"
                aria-modal="true"
                aria-label={title}
                tabIndex={-1}
                className="flex h-screen flex-col bg-card text-card-foreground focus:outline-none"
            >
                {/* No close (×) here: this is its own OS window, so the native
                    title-bar close and the footer button already close it. */}
                <div className="flex items-center border-b border-border px-5 py-3">
                    <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
                </div>
                <div className="mx-auto w-full max-w-3xl flex-1 overflow-y-auto p-6">{children}</div>
                {footer && (
                    <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
                        {footer}
                    </div>
                )}
            </div>
        );
    }

    return createPortal(
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden="true" />
            <div
                ref={panelRef}
                role="dialog"
                aria-modal="true"
                aria-label={title}
                tabIndex={-1}
                className="relative z-10 flex w-full max-w-lg flex-col rounded-xl border border-border bg-card text-card-foreground shadow-lg focus:outline-none"
            >
                <div className="flex items-center justify-between border-b border-border p-4">
                    <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close"
                        className="rounded p-1 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                        <X size={18} />
                    </button>
                </div>
                <div className="max-h-[85vh] overflow-y-auto p-4">{children}</div>
                {footer && (
                    <div className="flex items-center justify-end gap-2 border-t border-border p-4">
                        {footer}
                    </div>
                )}
            </div>
        </div>,
        document.body,
    );
}
