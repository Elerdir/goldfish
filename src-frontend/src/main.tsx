import { StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createRouter } from "@tanstack/react-router";

import { ThemeProvider } from "@/providers/ThemeProvider";
import { I18nProvider } from "@/providers/I18nProvider";
import { SettingsProvider } from "@/providers/SettingsProvider";
import { VaultProvider } from "@/providers/VaultProvider";
import { EntryWindow } from "@/screens/EntryWindow";
import { LogWindow } from "@/screens/LogWindow";
import { SettingsWindow } from "@/screens/SettingsWindow";
import { routeTree } from "@/routeTree.gen";
import "@/index.css";

const router = createRouter({
    routeTree,
    defaultPreload: "intent",
    scrollRestoration: true,
});

declare module "@tanstack/react-router" {
    interface Register {
        router: typeof router;
    }
}

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            staleTime: 30_000,
            retry: 1,
            refetchOnWindowFocus: false,
        },
    },
});

const rootElement = document.getElementById("root");
if (!rootElement) {
    throw new Error("root element missing");
}

// Secondary windows are selected by a `?view=` query param. The log window is
// minimal (reads from disk); settings/entry windows and the main app all share
// the full provider stack. The window-resize logic in VaultProvider self-limits
// to the "main" window, so sub-windows aren't resized.
const params = new URLSearchParams(window.location.search);
const view = params.get("view");

let content: ReactNode;
if (view === "logs") {
    content = <LogWindow />;
} else {
    const id = params.get("id");
    const root =
        view === "settings" ? (
            <SettingsWindow />
        ) : view === "entry" ? (
            <EntryWindow entryId={id && id !== "new" ? id : null} />
        ) : (
            <RouterProvider router={router} />
        );
    content = (
        <SettingsProvider>
            <QueryClientProvider client={queryClient}>
                <VaultProvider>{root}</VaultProvider>
            </QueryClientProvider>
        </SettingsProvider>
    );
}

createRoot(rootElement).render(
    <StrictMode>
        <I18nProvider>
            <ThemeProvider defaultTheme="system" storageKey="goldfish-theme">
                {content}
            </ThemeProvider>
        </I18nProvider>
    </StrictMode>,
);
