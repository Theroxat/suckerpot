import { Component, lazy, Suspense, useCallback, useState, type ReactNode } from "react"
import { SENSORS, type LiveEvent } from "@/lib/api"
import { SENSOR_META } from "@/lib/sensors"
import { cn } from "@/lib/utils"
import { FallbackMap } from "./fallback-map"
import { webglAvailable } from "./palette"
import { useSiteHome } from "./use-site"

// The globe pulls in three.js: it gets its own chunk, fetched only when this card mounts.
const GlobeCanvas = lazy(() => import("./globe-canvas"))

class Boundary extends Component<
  { onError: () => void; children: ReactNode },
  { failed: boolean }
> {
  override state = { failed: false }
  static getDerivedStateFromError() {
    return { failed: true }
  }
  override componentDidCatch() {
    this.props.onError()
  }
  override render() {
    return this.state.failed ? null : this.props.children
  }
}

interface LiveGlobeProps {
  events: readonly LiveEvent[]
  paused: boolean
  className?: string
}

/** The globe card: the 3D view when WebGL works, a flat map when it does not. */
export function LiveGlobe({ events, paused, className }: LiveGlobeProps) {
  const site = useSiteHome()
  const [broken, setBroken] = useState(() => !webglAvailable())
  const markBroken = useCallback(() => setBroken(true), [])
  const home = site.data ? { lat: site.data.lat, lon: site.data.lon } : null
  const label = site.data?.label

  return (
    <div
      className={cn("relative overflow-hidden rounded-lg border bg-surface shadow-sm", className)}
    >
      <div
        className="absolute inset-x-0 top-0 bottom-14 sm:bottom-0"
        role="img"
        aria-label={
          label
            ? `Globe of recent attack origins, with arcs landing on ${label}`
            : "Globe of recent attack origins"
        }
      >
        {!home ? (
          <div className="flex size-full items-center justify-center" aria-hidden>
            <div className="size-2/3 max-h-80 max-w-80 animate-pulse rounded-full bg-accent" />
          </div>
        ) : broken ? (
          <div className="flex size-full items-center justify-center p-4">
            <FallbackMap events={events} home={home} />
          </div>
        ) : (
          <Boundary onError={() => setBroken(true)}>
            <Suspense
              fallback={
                <div className="flex size-full items-center justify-center" aria-hidden>
                  <div className="size-2/3 max-h-80 max-w-80 animate-pulse rounded-full bg-accent" />
                </div>
              }
            >
              <GlobeCanvas events={events} home={home} paused={paused} onUnavailable={markBroken} />
            </Suspense>
          </Boundary>
        )}
      </div>

      <div className="pointer-events-none absolute inset-x-4 bottom-3 flex flex-wrap items-end justify-between gap-x-4 gap-y-1">
        <ul
          aria-label="Sensor colours"
          className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-fg-muted"
        >
          {SENSORS.map((s) => {
            const meta = SENSOR_META[s]
            const Icon = meta.icon
            return (
              <li key={s} className="flex items-center gap-1.5">
                <Icon aria-hidden className={cn("size-3.5", meta.text)} />
                {meta.label}
              </li>
            )
          })}
        </ul>
        {label ? <p className="text-xs text-fg-subtle">Landing in {label}</p> : null}
      </div>
    </div>
  )
}
