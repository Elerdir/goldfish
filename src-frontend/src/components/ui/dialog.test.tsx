import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { Dialog } from "./dialog";

function Harness() {
    const [open, setOpen] = useState(false);
    return (
        <div>
            <button type="button" onClick={() => setOpen(true)}>
                open
            </button>
            <Dialog open={open} onClose={() => setOpen(false)} title="Test dialog">
                <button type="button">inside</button>
            </Dialog>
        </div>
    );
}

describe("Dialog accessibility", () => {
    it("exposes modal dialog semantics", async () => {
        const user = userEvent.setup();
        render(<Harness />);
        await user.click(screen.getByText("open"));
        const dialog = screen.getByRole("dialog");
        expect(dialog.getAttribute("aria-modal")).toBe("true");
        expect(dialog.getAttribute("aria-label")).toBe("Test dialog");
    });

    it("moves focus into the dialog on open and restores it on close", async () => {
        const user = userEvent.setup();
        render(<Harness />);
        const trigger = screen.getByText("open");
        trigger.focus();
        expect(document.activeElement).toBe(trigger);

        await user.click(trigger);
        // jsdom has no layout (offsetParent is always null), so the focus-trap
        // can't see the inner button; it falls back to focusing the panel — which
        // still verifies focus entered the dialog.
        const dialog = screen.getByRole("dialog");
        expect(document.activeElement).toBe(dialog);

        await user.keyboard("{Escape}");
        expect(screen.queryByRole("dialog")).toBeNull();
        expect(document.activeElement).toBe(trigger); // focus restored
    });
});
