import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react"

export type ThemePreference = "dark" | "light" | "system"
export type ResolvedTheme = "dark" | "light"

const STORAGE_KEY = "suckerpot.theme"
const LIGHT_QUERY = "(prefers-color-scheme: light)"

interface ThemeContextValue {
  preference: ThemePreference
  resolved: ResolvedTheme
  setPreference: (p: ThemePreference) => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

function readPreference(): ThemePreference {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === "dark" || v === "light" || v === "system") return v
  } catch {
    // Storage blocked: fall back to the system setting.
  }
  return "system"
}

/** Dark is the default; light only when the OS asks for it or the user picks it. */
function resolve(p: ThemePreference): ResolvedTheme {
  if (p !== "system") return p
  return window.matchMedia(LIGHT_QUERY).matches ? "light" : "dark"
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [preference, setPreferenceState] = useState<ThemePreference>(readPreference)
  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolve(readPreference()))

  useEffect(() => {
    const apply = () => {
      const r = resolve(preference)
      setResolved(r)
      document.documentElement.dataset.theme = r
    }
    apply()
    if (preference !== "system") return
    const mql = window.matchMedia(LIGHT_QUERY)
    mql.addEventListener("change", apply)
    return () => mql.removeEventListener("change", apply)
  }, [preference])

  const setPreference = useCallback((p: ThemePreference) => {
    setPreferenceState(p)
    try {
      localStorage.setItem(STORAGE_KEY, p)
    } catch {
      // Ignore: the choice just will not persist.
    }
  }, [])

  const value = useMemo(
    () => ({ preference, resolved, setPreference }),
    [preference, resolved, setPreference],
  )
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error("useTheme must be used inside ThemeProvider")
  return ctx
}
