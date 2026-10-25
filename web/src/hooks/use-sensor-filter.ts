import { useMemo } from "react"
import { useUrlParam } from "@/hooks/use-url-param"
import { formatSensors, parseSensors, type Sensor } from "@/lib/sensors"

/**
 * The sensor selection, synced to `?sensor=ssh,telnet`. An empty list means
 * "every sensor" (no filter); unknown names in the URL are ignored.
 */
export function useSensorFilter() {
  const [raw, setRaw] = useUrlParam("sensor")
  const sensors = useMemo(() => parseSensors(raw), [raw])
  const set = (next: readonly Sensor[]) => setRaw(formatSensors(next))
  return [sensors, set] as const
}

/** `undefined` for "no filter", so query keys and API params stay minimal. */
export function sensorParam(sensors: readonly Sensor[]): readonly Sensor[] | undefined {
  return sensors.length ? sensors : undefined
}
