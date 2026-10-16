import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
    {
        ignores: [
            "dist",
            "src/routeTree.gen.ts",
            "vite.config.ts",
            "tailwind.config.ts",
            "postcss.config.cjs",
            "eslint.config.js",
        ],
    },
    {
        extends: [js.configs.recommended, ...tseslint.configs.recommendedTypeChecked],
        files: ["**/*.{ts,tsx}"],
        languageOptions: {
            ecmaVersion: 2023,
            globals: globals.browser,
            parserOptions: {
                project: ["./tsconfig.json"],
                tsconfigRootDir: import.meta.dirname,
            },
        },
        plugins: {
            "react-hooks": reactHooks,
            "react-refresh": reactRefresh,
        },
        rules: {
            // react-hooks 7 "recommended" also enables the React Compiler rules (set-state-in-effect,
            // purity, …). They flag existing effects that need a careful refactor of their own, so
            // keep the classic pair for now and adopt the compiler rules in a separate change.
            "react-hooks/rules-of-hooks": "error",
            "react-hooks/exhaustive-deps": "warn",
            "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
            "@typescript-eslint/consistent-type-imports": ["error", { prefer: "type-imports" }],
            "@typescript-eslint/no-unused-vars": [
                "error",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
        },
    },
    {
        // TanStack Router route files export `Route` next to their components; with
        // autoCodeSplitting the router plugin handles hot reload of these files itself.
        files: ["src/routes/**/*.tsx"],
        rules: { "react-refresh/only-export-components": "off" },
    },
);
