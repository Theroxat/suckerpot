import { useCallback, useState } from "react"

/**
 * Whether a form's value differs from the last saved one. Compares plain JSON, so it fits the
 * small settings forms (strings, numbers, booleans, arrays). Call `markSaved(value)` after a
 * successful save; a form that remounts on new server data starts clean by itself.
 */
export function useUnsaved<T>(value: T): { unsaved: boolean; markSaved: (saved: T) => void } {
  const [base, setBase] = useState(() => JSON.stringify(value))
  const markSaved = useCallback((saved: T) => setBase(JSON.stringify(saved)), [])
  return { unsaved: JSON.stringify(value) !== base, markSaved }
}
