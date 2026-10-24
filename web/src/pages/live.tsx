import { useVirtualizer } from "@tanstack/react-virtual"
import { ArrowUp, Pause, Play, Radio, SearchX, WifiOff } from "lucide-react"
import { useEffect, useMemo, useRef, useState } from "react"
import { Link, useSearchParams } from "react-router"
import { useLiveFeed } from "@/app/use-live-feed"
import { EmptyState } from "@/components/empty-state"
import { SensorFilter } from "@/components/filter-bar"
import { LiveGlobe } from "@/components/globe/live-globe"
import { LiveEventRow } from "@/components/live-event-row"
import { StatTile } from "@/components/stat-tile"
import { PageHeader } from "@/components/page-header"
import { SkeletonList } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { SENSORS, isSensor } from "@/lib/api"
import { formatNumber, plural } from "@/lib/format"
import { deriveStats, formatSessions, liveFinding } from "@/lib/live-stats"
import { SENSOR_META } from "@/lib/sensors"
import { cn } from "@/lib/utils"

/** How long a freshly arrived row keeps its slide-in marker. */
const FRESH_MS = 1_000
/** Scroll offset (px) under which the user counts as "at the top". */
const TOP_SLACK = 8

export function LivePage() {
  const feed = useLiveFeed()
  const [params] = useSearchParams()
  const rawSensor = params.get("sensor")
  const sensor = isSensor(rawSensor) ? rawSensor : null

  const stats = useMemo(
    () => feed.stats ?? (feed.events.length ? deriveStats(feed.events) : null),
    [feed.stats, feed.events],
  )

  // --- Hold the view while the user reads: paused, scrolled away or hovering.
  const [paused, setPaused] = useState(false)
  const [scrolledAway, setScrolledAway] = useState(false)
  const [hovered, setHovered] = useState(false)
  // After "jump to latest" the pointer may still rest on the list: follow anyway.
  const [following, setFollowing] = useState(false)
  const held = paused || scrolledAway || (hovered && !following)
  const newest = feed.events[0]?.id ?? 0
  const [cutoff, setCutoff] = useState<number | null>(null)
  if (held && cutoff === null) setCutoff(newest)
  if (!held && cutoff !== null) setCutoff(null)
  const limit = held ? (cutoff ?? newest) : null

  // --- Mark rows that just arrived, for a calm slide-in.
  const [prevNewest, setPrevNewest] = useState<number | null>(null)
  const [freshAbove, setFreshAbove] = useState<number | null>(null)
  if (newest !== prevNewest) {
    setPrevNewest(newest)
    if (prevNewest !== null && prevNewest > 0) setFreshAbove(prevNewest)
  }
  useEffect(() => {
    if (freshAbove === null) return
    const t = setTimeout(() => setFreshAbove(null), FRESH_MS)
    return () => clearTimeout(t)
  }, [freshAbove])

  const matching = useMemo(
    () => (sensor ? feed.events.filter((e) => e.sensor === sensor) : feed.events),
    [feed.events, sensor],
  )
  const visible = useMemo(
    () => (limit === null ? matching : matching.filter((e) => e.id <= limit)),
    [matching, limit],
  )
  const pending = matching.length - visible.length

  // --- Virtualised list in its own scroll area.
  const scrollRef = useRef<HTMLDivElement>(null)
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Virtual, used as documented
  const virtualizer = useVirtualizer({
    count: visible.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 52,
    overscan: 8,
    getItemKey: (i) => visible[i]?.id ?? i,
  })

  const jumpToLatest = () => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0
    setScrolledAway(false)
    setFollowing(true)
    setPaused(false)
  }

  const waiting = feed.events.length === 0
  const connecting = waiting && (feed.status === "connecting" || feed.status === "reconnecting")
  const down = waiting && feed.status === "offline"

  return (
    <>
      <PageHeader
        title="Live"
        description={liveFinding(stats)}
        actions={
          <Button
            variant="outline"
            size="sm"
            aria-pressed={paused}
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? <Play aria-hidden /> : <Pause aria-hidden />}
            {paused ? "Resume" : "Pause"}
          </Button>
        }
      />

      <section
        aria-label="Events in the last minute"
        className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4"
      >
        {SENSORS.map((s) => (
          <StatTile
            key={s}
            sensor={s}
            label={SENSOR_META[s].label}
            value={stats?.by_sensor[s]?.events ?? 0}
            unit="events / min"
            unitShort="/ min"
            hint={formatSessions(stats?.by_sensor[s]?.sessions ?? 0)}
            href={`/attacks?sensor=${s}`}
          />
        ))}
      </section>

      <div className="mt-6 mb-3 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <SensorFilter />
        <p className="text-xs text-fg-subtle" aria-live="off">
          {paused
            ? `Paused. ${plural(pending, "new event")} waiting.`
            : feed.transport === "polling"
              ? "Live updates are unavailable, refreshing every 10 seconds."
              : "Newest first. Scroll or hover to hold the view."}
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_25rem] xl:grid-cols-[minmax(0,1fr)_27rem]">
        <LiveGlobe events={matching} paused={paused} className="h-80 sm:h-96 lg:h-auto" />
        <div
          className="relative overflow-hidden rounded-lg border bg-surface shadow-sm"
          onPointerEnter={(e) => e.pointerType === "mouse" && setHovered(true)}
          onPointerLeave={() => {
            setHovered(false)
            setFollowing(false)
          }}
        >
          {pending > 0 ? (
            <div className="pointer-events-none absolute inset-x-0 top-3 z-20 flex justify-center">
              <Button
                size="sm"
                className="pointer-events-auto animate-fade-in rounded-full shadow-md"
                onClick={jumpToLatest}
              >
                <ArrowUp aria-hidden />
                {plural(pending, "new event")} — jump to latest
              </Button>
            </div>
          ) : null}

          {connecting ? (
            <SkeletonList rows={10} className="h-[calc(100dvh-27rem)] min-h-96 overflow-hidden" />
          ) : down ? (
            <EmptyState
              variant="bare"
              icon={WifiOff}
              title="The live feed is unreachable"
              description="The dashboard keeps trying in the background. Events will appear here as soon as the connection is back."
              className="h-[calc(100dvh-27rem)] min-h-96"
            />
          ) : waiting ? (
            <EmptyState
              variant="bare"
              icon={Radio}
              title="Nothing has arrived yet"
              description="New events slide in here the moment a sensor records them."
              className="h-[calc(100dvh-27rem)] min-h-96"
            />
          ) : visible.length === 0 ? (
            <EmptyState
              variant="bare"
              icon={SearchX}
              title="No events from this sensor yet"
              description="Nothing from the selected sensor is in the live buffer. Show all sensors to see the rest."
              className="h-[calc(100dvh-27rem)] min-h-96"
              action={
                <Button asChild variant="outline" size="sm">
                  <Link to="/live">Show all sensors</Link>
                </Button>
              }
            />
          ) : (
            <div
              ref={scrollRef}
              onScroll={(e) => {
                const away = e.currentTarget.scrollTop > TOP_SLACK
                setScrolledAway(away)
                if (away) setFollowing(false)
              }}
              className="h-[calc(100dvh-27rem)] min-h-96 overflow-y-auto overscroll-contain lg:h-[calc(100dvh-25rem)]"
              tabIndex={-1}
            >
              <div
                role="list"
                aria-label="Live events"
                className="relative w-full"
                style={{ height: virtualizer.getTotalSize() }}
              >
                {virtualizer.getVirtualItems().map((v) => {
                  const e = visible[v.index]
                  if (!e) return null
                  return (
                    <div
                      key={v.key}
                      role="listitem"
                      data-index={v.index}
                      ref={virtualizer.measureElement}
                      className="absolute inset-x-0 top-0 border-b"
                      style={{ transform: `translateY(${v.start}px)` }}
                    >
                      <LiveEventRow
                        event={e}
                        stacked
                        isNew={freshAbove !== null && e.id > freshAbove}
                      />
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          <div
            className={cn(
              "flex items-center justify-between gap-3 border-t px-4 py-2.5 text-xs text-fg-subtle sm:px-5",
            )}
          >
            <span>{formatNumber(visible.length)} events in this tab</span>
            <Link to="/attacks" className="text-fg-muted hover:text-fg hover:underline">
              Browse all attacks
            </Link>
          </div>
        </div>
      </div>
    </>
  )
}
