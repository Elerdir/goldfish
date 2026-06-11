// Vitest setup for jsdom-based component/hook tests.

// jsdom doesn't implement matchMedia; ThemeProvider (and others) rely on it.
// Provide a minimal, controllable stub defaulting to "light" (no dark preference).
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
    window.matchMedia = (query: string): MediaQueryList => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
    });
}
