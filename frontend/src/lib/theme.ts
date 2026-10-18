import { useCallback, useEffect, useState } from "react";
import { playSwitch, switching } from "./themeSwitch";

/* Light / dark theme (2026-10-18). The theme is the data-theme attribute on <html>; styles.css keys every colour token on it.
   - First paint: the inline script in index.html sets it before the stylesheet and React load (no flash of the wrong theme). It repeats
     resolveTheme() below in plain JS; keep the two in step.
   - First visit: the system setting (prefers-color-scheme), dark when the system has no preference (the design's own theme).
   - The sun/moon button stores the choice in localStorage; every access is in try/catch, so with storage blocked the button still works for
     the visit and the next visit follows the system again. Nothing else is stored.
   - Without a stored choice the page follows the system setting live.
   - The button plays the comet / black-hole animation (lib/themeSwitch.ts); with reduced motion or without View Transitions it switches at
     once. The state, the button's label and the stored choice change on the click; clicks while the animation runs are ignored. */
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

/** Sets the attribute (and so every token): the globe reads the tokens in its own effect, so this comes before the state changes. */
export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
}

export function useTheme(): [Theme, (button?: HTMLElement) => void] {
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
      applyTheme(t);
      setTheme(t);
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  const toggle = useCallback((button?: HTMLElement) => {
    if (switching()) return;
    const next: Theme = theme === "dark" ? "light" : "dark";
    storeTheme(next);
    // the attribute changes once the animation has snapshotted the old page (playSwitch calls applyTheme then), or at once when it cannot animate
    if (!playSwitch(next, () => applyTheme(next), button ?? null)) applyTheme(next);
    setTheme(next);
  }, [theme]);

  return [theme, toggle];
}
