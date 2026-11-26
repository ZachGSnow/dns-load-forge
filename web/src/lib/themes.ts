export type ThemeId =
  | "system"
  | "light"
  | "dark"
  | "midnight"
  | "grove"
  | "tidal-ember"
  | "dusk"
  | "ink-wheat"

export interface ThemeOption {
  id: ThemeId
  label: string
  /** Palettes are dark themes that recolour every token. */
  palette?: boolean
  /** Swatch for the picker: background, card, primary. */
  swatch: [string, string, string]
}

export const THEMES: ThemeOption[] = [
  { id: "system", label: "System", swatch: ["#ffffff", "#0a0a0a", "#737373"] },
  { id: "light", label: "Light", swatch: ["#ffffff", "#f5f5f5", "#171717"] },
  { id: "dark", label: "Dark", swatch: ["#0a0a0a", "#141414", "#e5e5e5"] },
  {
    id: "midnight",
    label: "Midnight",
    palette: true,
    swatch: ["#0b0f14", "#121821", "#4ea6ff"],
  },
  {
    id: "grove",
    label: "Grove",
    palette: true,
    swatch: ["#1d2711", "#283618", "#dda15e"],
  },
  {
    id: "tidal-ember",
    label: "Tidal Ember",
    palette: true,
    swatch: ["#001219", "#04202b", "#4cc3c4"],
  },
  {
    id: "dusk",
    label: "Dusk",
    palette: true,
    swatch: ["#18233a", "#1f2d48", "#eaac8b"],
  },
  {
    id: "ink-wheat",
    label: "Ink & Wheat",
    palette: true,
    swatch: ["#04151f", "#0a2429", "#f07a2a"],
  },
]

/** The same key the original dashboard used, so a saved palette carries over. */
export const THEME_STORAGE_KEY = "dlf-theme"
export const DEFAULT_THEME: ThemeId = "dark"

export function isThemeId(value: unknown): value is ThemeId {
  return typeof value === "string" && THEMES.some((t) => t.id === value)
}

export function isPalette(id: ThemeId): boolean {
  return THEMES.some((t) => t.id === id && t.palette)
}

export function resolveMode(
  id: ThemeId,
  systemDark: boolean
): "light" | "dark" {
  if (id === "light") return "light"
  if (id === "system") return systemDark ? "dark" : "light"
  return "dark"
}
