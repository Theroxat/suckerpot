import { createContext, useCallback, useContext, useMemo, useState } from "react"

/**
 * Screenshot mode: when on, every address in the UI is masked
 * (203.0.113.42 -> 203.0.x.x), so screens of real data can be shared.
 * `?mask=1` / `?mask=0` in any URL sets it; the choice persists per browser.
 */
const STORAGE_KEY = "suckerpot.maskIps"

interface IpMaskContextValue {
  masked: boolean
  setMasked: (on: boolean) => void
}

const IpMaskContext = createContext<IpMaskContextValue>({
  masked: false,
  setMasked: () => undefined,
})

function store(on: boolean) {
  try {
    localStorage.setItem(STORAGE_KEY, on ? "1" : "0")
  } catch {
    // Storage blocked: the setting lasts for this tab only.
  }
}

function initial(): boolean {
  const flag = new URLSearchParams(window.location.search).get("mask")
  if (flag === "1" || flag === "0") {
    store(flag === "1")
    return flag === "1"
  }
  try {
    return localStorage.getItem(STORAGE_KEY) === "1"
  } catch {
    return false
  }
}

export function IpMaskProvider({ children }: { children: React.ReactNode }) {
  const [masked, setState] = useState(initial)
  const setMasked = useCallback((on: boolean) => {
    setState(on)
    store(on)
  }, [])
  const value = useMemo(() => ({ masked, setMasked }), [masked, setMasked])
  return <IpMaskContext.Provider value={value}>{children}</IpMaskContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useIpMask(): IpMaskContextValue {
  return useContext(IpMaskContext)
}
