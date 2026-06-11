import { describe, expect, it } from "vitest";

import { estimateStrength } from "@/lib/strength";

// Outside Tauri (the vitest/node environment), estimateStrength uses its
// built-in entropy heuristic rather than the Rust zxcvbn backend. The heuristic
// is deliberately conservative, so these expectations track its calibration.
describe("estimateStrength (heuristic fallback)", () => {
    it("returns 0 for an empty password", async () => {
        expect(await estimateStrength("")).toBe(0);
    });

    it("scores a short single-class password as weak", async () => {
        expect(await estimateStrength("abc")).toBeLessThanOrEqual(1);
    });

    it("scores a short password low and a long all-class one at the top", async () => {
        const short = await estimateStrength("Aa1!"); // 4 chars
        const long = await estimateStrength("Aa1!".repeat(12)); // 48 chars, all 4 classes
        expect(short).toBeLessThanOrEqual(1);
        expect(long).toBe(4);
        expect(long).toBeGreaterThan(short);
    });

    it("always returns a score within 0..4", async () => {
        for (const pw of ["", "a", "aA1!", "password", "x".repeat(200)]) {
            const score = await estimateStrength(pw);
            expect(score).toBeGreaterThanOrEqual(0);
            expect(score).toBeLessThanOrEqual(4);
        }
    });
});
