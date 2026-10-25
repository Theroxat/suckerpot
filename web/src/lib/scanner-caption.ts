import { plural } from "./format"

/** What the "hide research scanners" switch does to the numbers, in words. */
export function scannerCaption(hide: boolean, sessions: number | undefined): string {
  if (sessions === undefined) return " "
  if (sessions === 0) return "No research scanners in the last 24 h"
  const n = plural(sessions, "session")
  return hide ? `${n} hidden (last 24 h)` : `Showing ${n} from scanners (last 24 h)`
}
