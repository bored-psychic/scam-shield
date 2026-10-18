import { describe, expect, test } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { resolveTheme, storedTheme, storeTheme, THEME_KEY } from "./theme";
import Header from "../components/Header";

// npm test. The light / dark theme (2026-10-18): Y1 the rule that picks it, Y2 storage that is missing, blocked or holds junk, Y3 the inline
// script in index.html follows the same rule, Y4 the button's label, Y5 no hard-coded colour outside the token blocks. The browser side (toggle,
// reload, no flash, blocked storage on a real page, axe and pixel contrast in both themes) is e2e/theme.mjs, e2e/axe.mjs and e2e/contrast.mjs.
// the sources as text: through Vite's ?raw, except styles.css, which vitest turns into an empty string on import, so it is read from disk
// (node:fs through a dynamic import typed by hand: the project has no Node types)
import html from "../../index.html?raw";
const fs = (await import(/* @vite-ignore */ "node:" + "fs")) as { readFileSync: (path: URL, encoding: "utf8") => string };
const css = fs.readFileSync(new URL("../styles.css", import.meta.url), "utf8");
const CODE: Record<string, string> = {
  ...import.meta.glob<string>("../components/*.tsx", { query: "?raw", import: "default", eager: true }),
  ...import.meta.glob<string>(["./*.ts", "./*.tsx", "!./*.test.*"], { query: "?raw", import: "default", eager: true }),
};
const mem = (v: string | null) => ({ getItem: () => v, setItem: () => {} });
const blocked = { getItem: () => { throw new DOMException("blocked", "SecurityError"); }, setItem: () => { throw new DOMException("blocked", "SecurityError"); } };

describe("Y1 which theme", () => {
  test("a stored choice wins; without one the system decides, dark when it is not light", () => {
    expect(resolveTheme("light", false)).toBe("light");
    expect(resolveTheme("dark", true)).toBe("dark");
    expect(resolveTheme(null, true)).toBe("light");
    expect(resolveTheme(null, false)).toBe("dark");
  });
});

describe("Y2 storage", () => {
  test("reads only 'light' or 'dark'", () => {
    expect(storedTheme(mem("light"))).toBe("light");
    expect(storedTheme(mem("dark"))).toBe("dark");
    expect(storedTheme(mem("blue"))).toBeNull();
    expect(storedTheme(mem(null))).toBeNull();
    expect(storedTheme(null)).toBeNull();
  });
  test("blocked storage neither throws nor stores", () => {
    expect(storedTheme(blocked)).toBeNull();
    expect(storeTheme("light", blocked)).toBe(false);
    expect(storeTheme("light", null)).toBe(false);
    const saved: Record<string, string> = {};
    expect(storeTheme("dark", { setItem: (k, v) => { saved[k] = v; } })).toBe(true);
    expect(saved).toEqual({ [THEME_KEY]: "dark" });
  });
});

describe("Y3 the inline script in index.html", () => {
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
  test("runs before the app's module script and reads the same key and media query", () => {
    expect(script).toContain(`"${THEME_KEY}"`);
    expect(script).toContain('"(prefers-color-scheme: light)"');
    expect(script).toContain("try");
    expect(html.indexOf("<script>")).toBeLessThan(html.indexOf('<script type="module"'));
  });
  test("its pre-stylesheet background colours are the themes' --bg tokens", () => {
    const bg = (block: string) => /--bg: (#[0-9A-F]{6})/i.exec(block)?.[1];
    const dark = css.slice(css.indexOf(":root {"), css.indexOf(':root[data-theme="light"]'));
    const light = css.slice(css.indexOf(':root[data-theme="light"]'));
    expect(html).toContain(`html { background-color: ${bg(dark)}; }`);
    expect(html).toContain(`html[data-theme="light"] { background-color: ${bg(light)}; }`);
  });
});

describe("Y4 the theme button", () => {
  test("names the theme it switches to", () => {
    expect(renderToStaticMarkup(<Header theme="dark" onToggleTheme={() => {}} />)).toContain('aria-label="Switch to the light theme"');
    expect(renderToStaticMarkup(<Header theme="light" onToggleTheme={() => {}} />)).toContain('aria-label="Switch to the dark theme"');
  });
});

describe("Y5 every colour comes from a token", () => {
  const COLOUR = /#[0-9a-f]{3,8}\b|\brgba?\(\s*[\d.]|\bhsla?\(\s*[\d.]|\b0x[0-9a-f]{6}\b/gi;
  test("components and lib code name no colour", () => {
    expect(Object.keys(CODE).length).toBeGreaterThan(20);
    const hits = Object.entries(CODE).flatMap(([f, text]) => (text.match(COLOUR) ?? []).map((m) => `${f}: ${m}`));
    expect(hits).toEqual([]);
  });
  test("styles.css names colours only in the two token blocks (and the black of the glass rim's mask, which is alpha only)", () => {
    const rules = css.slice(css.indexOf("/* The page background lives on <html>"));
    expect(css.indexOf("/* The page background lives on <html>")).toBeGreaterThan(0);
    expect(rules.length).toBeGreaterThan(20000);
    const hits = (rules.match(COLOUR) ?? []).filter((m) => m !== "#000");
    expect(hits).toEqual([]);
  });
});
