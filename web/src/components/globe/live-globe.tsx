import {
  Component,
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react"
import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { SegmentedControl } from "@/components/segmented-control"
import { aggregateSources } from "@/components/map/activity"
import { WorldMap } from "@/components/map/world-map"
import { useUrlParam } from "@/hooks/use-url-param"
import type { LiveEvent } from "@/lib/api"
import { formatNumber } from "@/lib/format"
import { FAMILY_META, SENSOR_FAMILIES } from "@/lib/sensors"
import { cn } from "@/lib/utils"
import { webglAvailable } from "./palette"
import { useSiteHome } from "./use-site"

// The globe pulls in three.js: it gets its own chunk, fetched only when the globe view is on.
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

export type MapView = "map" | "globe"
const VIEW_KEY = "suckerpot.live.view"

/** `?view=map|globe`, else the last choice on this browser, else the flat map. */
function useMapView() {
  const [raw, setRaw] = useUrlParam("view")
  const stored = (() => {
    try {
      return localStorage.getItem(VIEW_KEY)
    } catch {
      return null
    }
  })()
  const view: MapView = (raw ?? stored) === "globe" ? "globe" : "map"
  const set = (next: MapView) => {
    try {
      localStorage.setItem(VIEW_KEY, next)
    } catch {
      // Not remembered in private mode; the URL still carries it.
    }
    setRaw(next === "map" ? null : next)
  }
  return [view, set] as const
}

/** A clock for fading: ticks every few seconds, not every frame. */
function useTick(ms: number) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(t)
  }, [ms])
  return now
}

interface LiveMapProps {
  /** Newest first, already filtered by the page. */
  events: readonly LiveEvent[]
  paused: boolean
  className?: string
}

/**
 * The Live attack map: a flat world map by default, the 3D globe on request.
 * Both draw the same calm picture: the last 15 minutes of sources, one arc per
 * country, thicker for more events and fading with age. The footer names the
 * top sources (each opens the filtered Attacks view) and the family colours.
 */
export function LiveMap({ events, paused, className }: LiveMapProps) {
  const site = useSiteHome()
  const [view, setView] = useMapView()
  const [broken, setBroken] = useState(() => !webglAvailable())
  const markBroken = useCallback(() => setBroken(true), [])
  const home = site.data ? { lat: site.data.lat, lon: site.data.lon } : null
  const label = site.data?.label
  const tick = useTick(5_000)
  // Recomputed on every new event, and on the tick so old sources fade.
  const now = Math.max(tick, Date.parse(events[0]?.ts ?? "") || 0)
  const activity = useMemo(() => aggregateSources(events, now), [events, now])
  const globe = view === "globe" && !broken
  const top = activity.sources.slice(0, 5)

  return (
    <div
      className={cn(
        "flex flex-col overflow-hidden rounded-lg border bg-surface shadow-sm",
        className,
      )}
    >
      <div className="relative min-h-0 flex-1">
        {!home ? (
          <div className="flex size-full items-center justify-center" aria-hidden>
            <div className="h-2/3 w-5/6 animate-pulse rounded-lg bg-accent" />
          </div>
        ) : globe ? (
          <div
            className="absolute inset-0"
            role="img"
            aria-label={`Globe of recent attack origins, with arcs landing on ${label ?? "the sensors"}`}
          >
            <Boundary onError={markBroken}>
              <Suspense
                fallback={
                  <div className="flex size-full items-center justify-center" aria-hidden>
                    <div className="size-2/3 max-h-80 max-w-80 animate-pulse rounded-full bg-accent" />
                  </div>
                }
              >
                <GlobeCanvas
                  events={events}
                  sources={activity.sources}
                  now={now}
                  home={home}
                  paused={paused}
                  onUnavailable={markBroken}
                />
              </Suspense>
            </Boundary>
          </div>
        ) : (
          <WorldMap
            activity={activity}
            events={events}
            home={home}
            homeLabel={label}
            paused={paused}
            now={now}
          />
        )}
        <div className="absolute top-3 left-3">
          <SegmentedControl
            label="Map style"
            value={globe ? "globe" : "map"}
            onChange={setView}
            className="bg-surface-raised/90 shadow-sm backdrop-blur-sm"
            options={[
              { value: "map", label: "Map" },
              {
                value: "globe",
                label: "Globe",
                ariaLabel: broken ? "Globe (needs WebGL, unavailable here)" : "Globe",
              },
            ]}
          />
        </div>
      </div>

      <div className="space-y-2 border-t px-4 py-3 text-xs sm:px-5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <span className="text-fg-subtle">Top sources, 15 min</span>
          {top.length ? (
            <ul aria-label="Top sources in the last 15 minutes" className="contents">
              {top.map((s, i) => (
                <li key={s.country} className={cn(i >= 3 && "hidden sm:block")}>
                  <Link
                    to={`/attacks?country=${s.country}`}
                    className="-mx-1 inline-flex items-center gap-1.5 rounded-sm px-1 py-0.5 text-fg-muted transition-colors hover:bg-surface-hover hover:text-fg"
                  >
                    <CountryFlag code={s.country} />
                    <span className="font-medium text-fg">{s.country}</span>
                    <span className="tabular-nums">{formatNumber(s.events)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <span className="text-fg-muted">No located events yet</span>
          )}
          {activity.unlocated ? (
            <span className="text-fg-subtle">+ {formatNumber(activity.unlocated)} unlocated</span>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <ul
            aria-label="Arc colours by sensor family"
            className="flex flex-wrap gap-x-4 gap-y-1 text-fg-muted"
          >
            {SENSOR_FAMILIES.map((f) => {
              const fam = FAMILY_META[f]
              return (
                <li key={f} className="flex items-center gap-1.5">
                  <span aria-hidden className={cn("h-0.5 w-3 rounded-full", fam.fill)} />
                  {fam.label}
                </li>
              )
            })}
          </ul>
          {label ? <p className="text-fg-subtle">Landing in {label}</p> : null}
        </div>
      </div>
    </div>
  )
}
