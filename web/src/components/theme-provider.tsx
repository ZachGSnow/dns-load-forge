import * as React from "react"

import {
  DEFAULT_THEME,
  THEME_STORAGE_KEY,
  isPalette,
  isThemeId,
  resolveMode,
  type ThemeId,
} from "@/lib/themes"

const COLOR_SCHEME_QUERY = "(prefers-color-scheme: dark)"

interface ThemeState {
  theme: ThemeId
  mode: "light" | "dark"
  setTheme: (theme: ThemeId) => void
}

const ThemeContext = React.createContext<ThemeState | undefined>(undefined)

function readStoredTheme(): ThemeId {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    if (isThemeId(stored)) return stored
  } catch {
    // Storage blocked: the default theme, not remembered.
  }
  return DEFAULT_THEME
}

function subscribeScheme(onChange: () => void) {
  const query = window.matchMedia(COLOR_SCHEME_QUERY)
  query.addEventListener("change", onChange)
  return () => query.removeEventListener("change", onChange)
}

const systemPrefersDark = () =>
  window.matchMedia?.(COLOR_SCHEME_QUERY).matches ?? true

/** Same rules as the pre-paint script in index.html, which must agree with this. */
function applyToDocument(theme: ThemeId, mode: "light" | "dark") {
  const root = document.documentElement
  root.classList.remove("light", "dark")
  root.classList.add(mode)
  if (isPalette(theme)) root.setAttribute("data-theme", theme)
  else root.removeAttribute("data-theme")
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = React.useState<ThemeId>(readStoredTheme)
  const systemDark = React.useSyncExternalStore(
    subscribeScheme,
    systemPrefersDark,
    () => true
  )
  const mode = resolveMode(theme, systemDark)

  React.useEffect(() => {
    applyToDocument(theme, mode)
  }, [theme, mode])

  const setTheme = React.useCallback((next: ThemeId) => {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next)
    } catch {
      // Storage blocked: applied for this page only.
    }
    setThemeState(next)
  }, [])

  const value = React.useMemo(
    () => ({ theme, mode, setTheme }),
    [theme, mode, setTheme]
  )
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme(): ThemeState {
  const context = React.useContext(ThemeContext)
  if (!context) throw new Error("useTheme must be used within a ThemeProvider")
  return context
}
