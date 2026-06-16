import { writable } from "svelte/store";

export type Theme = "light" | "dark";

const KEY = "theme";

function initialTheme(): Theme {
  const saved = localStorage.getItem(KEY);
  if (saved === "light" || saved === "dark") {
    return saved;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export const theme = writable<Theme>(initialTheme());

theme.subscribe((value) => {
  document.documentElement.dataset.theme = value;
  try {
    localStorage.setItem(KEY, value);
  } catch {
    /* storage may be blocked; the theme still applies for this session */
  }
});

export function toggleTheme(): void {
  theme.update((value) => (value === "dark" ? "light" : "dark"));
}
