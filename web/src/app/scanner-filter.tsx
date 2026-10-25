import { useQueryClient } from "@tanstack/react-query"
import { createContext, use, useCallback, useMemo, useState } from "react"
import { setIncludeBenign } from "@/lib/api"
import { LiveFeedContext } from "./use-live-feed"

/**
 * "Hide research scanners": known, harmless internet crawlers (Censys, Shodan...) are labelled
 * `benign` at ingest and left out of every list, chart and feed unless this switch is off.
 * On by default. `?scanners=show` / `?scanners=hide` in any URL sets it; the choice persists per
 * browser. The flag lives in the API client (`setIncludeBenign`), so pages do not pass it around.
 */
const STORAGE_KEY = "suckerpot.hideScanners"

interface ScannerFilterValue {
  /** True when research scanners are hidden (the default). */
  hide: boolean
  setHide: (on: boolean) => void
}

const ScannerFilterContext = createContext<ScannerFilterValue>({
  hide: true,
  setHide: () => undefined,
})

function store(hide: boolean) {
  try {
    localStorage.setItem(STORAGE_KEY, hide ? "1" : "0")
  } catch {
    // Storage blocked: the setting lasts for this tab only.
  }
}

function initial(): boolean {
  const flag = new URLSearchParams(window.location.search).get("scanners")
  let hide = true
  if (flag === "show" || flag === "hide") {
    hide = flag === "hide"
    store(hide)
  } else {
    try {
      hide = localStorage.getItem(STORAGE_KEY) !== "0"
    } catch {
      hide = true
    }
  }
  setIncludeBenign(!hide)
  return hide
}

export function ScannerFilterProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const live = use(LiveFeedContext)
  const [hide, setState] = useState(initial)
  const setHide = useCallback(
    (on: boolean) => {
      setIncludeBenign(!on)
      setState(on)
      store(on)
      // Every cached answer was computed with the old setting.
      void queryClient.invalidateQueries()
      live?.restart()
    },
    [queryClient, live],
  )
  const value = useMemo(() => ({ hide, setHide }), [hide, setHide])
  return <ScannerFilterContext value={value}>{children}</ScannerFilterContext>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useScannerFilter(): ScannerFilterValue {
  return use(ScannerFilterContext)
}
