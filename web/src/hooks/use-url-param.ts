import { useSearchParams } from "react-router"

/** Read and write one URL search param, keeping the others. */
export function useUrlParam(param: string) {
  const [params, setParams] = useSearchParams()
  const value = params.get(param)
  const set = (next: string | null) => {
    setParams(
      (prev) => {
        const p = new URLSearchParams(prev)
        if (next === null || next === "") p.delete(param)
        else p.set(param, next)
        return p
      },
      { preventScrollReset: true },
    )
  }
  return [value, set] as const
}
