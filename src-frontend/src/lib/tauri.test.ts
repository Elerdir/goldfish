import { describe, expect, it } from "vitest";

import { asCommandError } from "@/lib/tauri";

describe("asCommandError", () => {
    it("passes through a well-formed CommandError", () => {
        expect(asCommandError({ kind: "invalid_password", message: "nope" })).toEqual({
            kind: "invalid_password",
            message: "nope",
        });
    });

    it("defaults message to an empty string when it is missing", () => {
        expect(asCommandError({ kind: "storage" })).toEqual({ kind: "storage", message: "" });
    });

    it("wraps a plain string error as unknown", () => {
        expect(asCommandError("boom")).toEqual({ kind: "unknown", message: "boom" });
    });

    it("wraps an unrecognized shape as unknown", () => {
        expect(asCommandError(42)).toEqual({ kind: "unknown", message: "unknown error" });
        expect(asCommandError(null)).toEqual({ kind: "unknown", message: "unknown error" });
    });
});
