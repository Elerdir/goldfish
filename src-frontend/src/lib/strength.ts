/**
 * Password strength estimation.
 *
 * Backed by the Rust `zxcvbn` crate via IPC (debounced by the caller). In a
 * plain browser (no Tauri backend, e.g. dev preview) it falls back to a light
 * entropy heuristic so the meter still moves.
 */

import { invoke } from "@tauri-apps/api/core";

import { isTauri } from "@/lib/tauri";

function heuristicScore(password: string): number {
    if (!password) return 0;
    let classes = 0;
    if (/[a-z]/.test(password)) classes += 1;
    if (/[A-Z]/.test(password)) classes += 1;
    if (/\d/.test(password)) classes += 1;
    if (/[^a-zA-Z0-9]/.test(password)) classes += 1;
    const bits = (password.length * Math.log2(Math.max(classes, 1) * 26)) / 4;
    if (password.length < 8 || classes <= 1) return Math.min(bits > 20 ? 1 : 0, 1);
    if (bits < 40) return 2;
    if (bits < 70) return 3;
    return 4;
}

/** Returns a 0–4 strength score (0 = empty/weakest, 4 = strongest). */
export async function estimateStrength(password: string): Promise<number> {
    if (password.length === 0) return 0;
    if (!isTauri()) return heuristicScore(password);
    try {
        return await invoke<number>("estimate_strength", { password });
    } catch {
        return heuristicScore(password);
    }
}
