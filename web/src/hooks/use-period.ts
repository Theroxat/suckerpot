import { useUrlParam } from "@/hooks/use-url-param"
import { DEFAULT_DAYS, parseDays } from "@/lib/defend"

/** The look-back window in days, kept in the URL (`?days=`). 30 is the default and stays bare. */
export function usePeriod() {
  const [raw, setRaw] = useUrlParam("days")
  const days = parseDays(raw)
  return [days, (d: number) => setRaw(d === DEFAULT_DAYS ? null : String(d))] as const
}
