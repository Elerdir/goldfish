/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";
import path from "node:path";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(() => ({
    plugins: [TanStackRouterVite({ target: "react", autoCodeSplitting: true }), react()],
    resolve: {
        alias: { "@": path.resolve(__dirname, "./src") },
    },
    test: {
        environment: "jsdom",
        globals: true,
        setupFiles: ["./src/test/setup.ts"],
        css: false,
    },
    clearScreen: false,
    server: {
        port: 5173,
        strictPort: true,
        host: host ?? false,
        watch: { ignored: ["**/src-tauri/**", "**/target/**", "**/crates/**"] },
        ...(host ? { hmr: { protocol: "ws" as const, host, port: 5174 } } : {}),
    },
    envPrefix: ["VITE_", "TAURI_ENV_*"],
    build: {
        target: ["es2022", "chrome120", "safari17"],
        minify: "esbuild" as const,
        sourcemap: false,
    },
}));
