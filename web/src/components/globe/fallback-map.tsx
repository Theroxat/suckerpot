import { useMemo } from "react"
import type { LiveEvent } from "@/lib/api"
import { latestDistinctArcs } from "./arc-queue"
import { landDots } from "./data/land-dots"
import type { GeoPoint } from "./geo"
import { SENSOR_META } from "@/lib/sensors"
import { isSensor } from "@/lib/api"

const W = 360
const H = 150
const LAT_MAX = 84
const LAT_MIN = -56
const x = (lon: number) => ((lon + 180) / 360) * W
const y = (lat: number) => ((LAT_MAX - lat) / (LAT_MAX - LAT_MIN)) * H

/**
 * Flat map for browsers without WebGL: the same land dots and sensor-coloured origins,
 * drawn as plain SVG. Origins are drawn as short lines to the home position.
 */
export function FallbackMap({ events, home }: { events: readonly LiveEvent[]; home: GeoPoint }) {
  const land = useMemo(() => {
    const d = landDots()
    let path = ""
    for (let i = 0; i < d.length; i += 2) {
      path += `M${x(d[i + 1] ?? 0).toFixed(1)} ${y(d[i] ?? 0).toFixed(1)}h.9`
    }
    return path
  }, [])
  const arcs = useMemo(() => latestDistinctArcs(events, home, 24), [events, home])

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="size-full"
      role="img"
      aria-label="Flat map of recent attack origins, drawn as lines towards the sensors"
      preserveAspectRatio="xMidYMid meet"
    >
      <path
        d={land}
        stroke="var(--fg-subtle)"
        strokeOpacity={0.5}
        strokeWidth={1.1}
        strokeLinecap="round"
      />
      {arcs.map((a) => {
        const hue = isSensor(a.sensor) ? SENSOR_META[a.sensor].cssVar : "var(--fg-muted)"
        const x1 = x(a.from.lon)
        const y1 = y(a.from.lat)
        const x2 = x(a.to.lon)
        const y2 = y(a.to.lat)
        const cy = Math.min(y1, y2) - Math.abs(x2 - x1) * 0.18
        return (
          <path
            key={a.id}
            d={`M${x1} ${y1}Q${(x1 + x2) / 2} ${cy} ${x2} ${y2}`}
            fill="none"
            stroke={hue}
            strokeOpacity={0.7}
            strokeWidth={0.5}
          />
        )
      })}
      <circle cx={x(home.lon)} cy={y(home.lat)} r={1.8} fill="var(--fg)" />
    </svg>
  )
}
