import { useCallback, useEffect, useRef, useState } from "react"

/** Copy text to the clipboard; `copied` stays true for 1.5 s. */
export function useCopy() {
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current)
    },
    [],
  )

  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }, [])

  return { copied, copy }
}
