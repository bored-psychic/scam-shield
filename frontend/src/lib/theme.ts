import { useCallback, useEffect, useState } from "react";

/* Light / dark theme (2026-10-18). The theme is the data-theme attribute on <html>; styles.css keys every colour token on it.
   - First paint: the inline script in index.html sets it before the stylesheet and React load (no flash of the wrong theme). It repeats
     resolveTheme() below in plain JS; keep the two in step.
   - First visit: the system setting (prefers-color-scheme), dark when the system has no preference (the design's own theme).
   - The sun/moon button stores the choice in localStorage; every access is in try/catch, so with storage blocked the button still works for
     the visit and the next visit follows the system again. Nothing else is stored.
   - Without a stored choice the page follows the system setting live. */
export type Theme = "light" | "dark";
export const THEME_KEY = "scam-shield-theme";
const LIGHT_QUERY = "(prefers-color-scheme: light)";

export function storedTheme(storage: Pick<Storage, "getItem"> | null = safeStorage()): Theme | null {
  try {
    const v = storage?.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

export function storeTheme(theme: Theme, storage: Pick<Storage, "setItem"> | null = safeStorage()): boolean {
  try {
    storage?.setItem(THEME_KEY, theme);
    return !!storage;
  } catch {
    return false;
  }
}

/** The theme to show: the stored choice, else the system's. */
export function resolveTheme(stored: Theme | null, systemLight: boolean): Theme {
  return stored ?? (systemLight ? "light" : "dark");
}

function safeStorage(): Storage | null {
  try {
    return window.localStorage;   // the getter itself throws where storage is blocked
  } catch {
    return null;
  }
}

function systemLight(): boolean {
  return typeof matchMedia === "function" && matchMedia(LIGHT_QUERY).matches;
}

/** Sets the attribute (and so every token) now, before React renders: the globe reads the tokens in its own effect. */
export function applyTheme(theme: Theme, animate: boolean) {
  const root = document.documentElement;
  if (animate) {   // a short colour cross-fade on a button press; never on load, never with reduced motion
    root.classList.add("theming");
    window.setTimeout(() => root.classList.remove("theming"), 320);
  }
  root.dataset.theme = theme;
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    if (typeof document === "undefined") return "dark";   // a server render (the vitest page tests)
    const t = document.documentElement.dataset.theme;
    return t === "light" || t === "dark" ? t : resolveTheme(storedTheme(), systemLight());
  });

  useEffect(() => {   // no stored choice: follow the system setting when it changes
    if (typeof matchMedia !== "function") return;
    const mq = matchMedia(LIGHT_QUERY);
    const onChange = () => {
      if (storedTheme() !== null) return;
      const t = resolveTheme(null, mq.matches);
      applyTheme(t, false);
      setTheme(t);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    const reduce = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
    applyTheme(next, !reduce);
    storeTheme(next);
    setTheme(next);
  }, [theme]);

  return [theme, toggle];
}
