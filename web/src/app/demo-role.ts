/**
 * Which account the mock and demo builds pretend to be. `?as=viewer` previews the read-only
 * shell, `?as=first-login` the "Set your password" screen, `?as=admin` (or nothing) the default.
 * The choice survives in-app navigation (which drops the query) through sessionStorage.
 */
export type DemoMode = "admin" | "viewer" | "first-login"

const KEY = "sp-demo-mode"
const MODES: readonly DemoMode[] = ["admin", "viewer", "first-login"]

function isMode(value: string | null): value is DemoMode {
  return value !== null && (MODES as readonly string[]).includes(value)
}

export function demoMode(): DemoMode {
  if (typeof window === "undefined") return "admin"
  const asked = new URLSearchParams(window.location.search).get("as")
  try {
    if (isMode(asked)) {
      window.sessionStorage.setItem(KEY, asked)
      return asked
    }
    const stored = window.sessionStorage.getItem(KEY)
    if (isMode(stored)) return stored
  } catch {
    // Storage can be blocked: fall back to the query alone.
  }
  return isMode(asked) ? asked : "admin"
}
