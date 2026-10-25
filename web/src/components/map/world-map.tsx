import { Minus, Plus } from "lucide-react"
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react"
import { useNavigate } from "react-router"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import type { LiveEvent } from "@/lib/api"
import { countryName, formatNumber, plural } from "@/lib/format"
import { FAMILY_META, SENSOR_META } from "@/lib/sensors"
import { cn } from "@/lib/utils"
import { globeFrozen } from "@/components/globe/palette"
import type { GeoPoint } from "@/components/globe/geo"
import { ACTIVE_MS, ageOpacity, countWeight, type Activity, type Source } from "./activity"
import { BORDERS_PATH, LAND_PATH } from "./data/world-paths"
import { MAP_WIDTH, project } from "./projection"

// --- Viewport -----------------------------------------------------------------

interface View {
  cx: number
  cy: number
  /** Visible width in map units. */
  vw: number
}

interface Box {
  x0: number
  y0: number
  x1: number
  y1: number
}

function boxOf(corners: readonly (readonly [number, number])[]): Box {
  const pts = corners.map(([lat, lon]) => project(lat, lon))
  return {
    x0: Math.min(...pts.map((p) => p[0])),
    x1: Math.max(...pts.map((p) => p[0])),
    y0: Math.min(...pts.map((p) => p[1])),
    y1: Math.max(...pts.map((p) => p[1])),
  }
}

/** The inhabited world: no polar caps, no Antarctica. */
const WORLD: Box = { x0: 0, x1: MAP_WIDTH, y0: project(78, 0)[1], y1: project(-56, 0)[1] }
/** Europe and its rim, where most real attackers sit relative to a Swiss home. */
const EUROPE: Box = boxOf([
  [63, -14],
  [63, 40],
  [33, -14],
  [33, 40],
  [48, 12],
])

export type MapPreset = "world" | "europe"
const PRESETS: Record<MapPreset, Box> = { world: WORLD, europe: EUROPE }

function fit(box: Box, aspect: number, margin = 0.04): View {
  const bw = (box.x1 - box.x0) * (1 + margin)
  const bh = (box.y1 - box.y0) * (1 + margin)
  return { cx: (box.x0 + box.x1) / 2, cy: (box.y0 + box.y1) / 2, vw: Math.max(bw, bh * aspect) }
}

const MIN_VW = 70

function clampView(v: View, aspect: number): View {
  const maxVw = fit(WORLD, aspect, 0.06).vw
  const vw = Math.min(maxVw, Math.max(MIN_VW, v.vw))
  const vh = vw / aspect
  const cx = Math.min(
    WORLD.x1 - Math.min(vw, MAP_WIDTH) / 2,
    Math.max(Math.min(vw, MAP_WIDTH) / 2, v.cx),
  )
  const midY = (WORLD.y0 + WORLD.y1) / 2
  const spanY = WORLD.y1 - WORLD.y0
  const cy = vh >= spanY ? midY : Math.min(WORLD.y1 - vh / 2, Math.max(WORLD.y0 + vh / 2, v.cy))
  return { cx, cy, vw }
}

const PRESET_KEY = "suckerpot.map.preset"

function storedPreset(): MapPreset {
  try {
    return localStorage.getItem(PRESET_KEY) === "world" ? "world" : "europe"
  } catch {
    return "europe"
  }
}

// --- Geometry -------------------------------------------------------------------

/** A gentle quadratic curve from the source to home, bowing north. Null for the same point. */
function arcPath(from: [number, number], to: [number, number]): string | null {
  const dx = to[0] - from[0]
  const dy = to[1] - from[1]
  const len = Math.hypot(dx, dy)
  if (len < 0.6) return null
  // Perpendicular, pointing up (towards smaller y).
  let px = -dy / len
  let py = dx / len
  if (py > 0) {
    px = -px
    py = -py
  }
  const bow = Math.min(len * 0.22, 60)
  const mx = (from[0] + to[0]) / 2 + px * bow
  const my = (from[1] + to[1]) / 2 + py * bow
  const f = (n: number) => n.toFixed(2)
  return `M${f(from[0])} ${f(from[1])}Q${f(mx)} ${f(my)} ${f(to[0])} ${f(to[1])}`
}

interface Dash {
  key: number
  country: string
  family: string
}

const MAX_DASHES = 14
const DASH_MS = 1_700

// --- Component -------------------------------------------------------------------

interface WorldMapProps {
  activity: Activity
  /** Newest first; only used to spot new events for the travelling dash. */
  events: readonly LiveEvent[]
  home: GeoPoint
  homeLabel?: string | undefined
  paused: boolean
  now: number
  className?: string
}

/**
 * The flat attack map (Equal Earth). Recent sources stay on screen as arcs to
 * home, thicker for more events and fading with age; a new event sends one
 * short dash along its arc. Wheel, drag, pinch and the keyboard pan and zoom.
 */
export function WorldMap({
  activity,
  events,
  home,
  homeLabel,
  paused,
  now,
  className,
}: WorldMapProps) {
  const reduced = useReducedMotion()
  const frozen = globeFrozen()
  const still = reduced || frozen
  const navigate = useNavigate()
  const hostRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ w: 800, h: 450 })
  const aspect = size.w / Math.max(1, size.h)
  const [preset, setPreset] = useState<MapPreset>(storedPreset)
  const [view, setView] = useState<View | null>(null)
  const anim = useRef<number | null>(null)

  // Measure, and fit the preset on first layout and whenever the shape changes.
  useLayoutEffect(() => {
    const el = hostRef.current
    if (!el) return
    const measure = () => {
      const w = el.clientWidth
      const h = el.clientHeight
      if (w > 0 && h > 0) setSize((s) => (s.w === w && s.h === h ? s : { w, h }))
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const [fittedFor, setFittedFor] = useState<string | null>(null)
  const fitKey = `${size.w}x${size.h}`
  if (fittedFor !== fitKey) {
    setFittedFor(fitKey)
    setView(clampView(fit(PRESETS[preset], aspect), aspect))
  }
  const v = view ?? fit(PRESETS[preset], aspect)

  const stopAnim = () => {
    if (anim.current !== null) cancelAnimationFrame(anim.current)
    anim.current = null
  }
  const animateTo = useCallback(
    (target: View) => {
      stopAnim()
      const to = clampView(target, aspect)
      if (still) {
        setView(to)
        return
      }
      const from = view ?? to
      const start = performance.now()
      const step = (t: number) => {
        const k = Math.min(1, (t - start) / 520)
        const e = 1 - (1 - k) ** 3
        setView({
          cx: from.cx + (to.cx - from.cx) * e,
          cy: from.cy + (to.cy - from.cy) * e,
          vw: Math.exp(Math.log(from.vw) + (Math.log(to.vw) - Math.log(from.vw)) * e),
        })
        anim.current = k < 1 ? requestAnimationFrame(step) : null
      }
      anim.current = requestAnimationFrame(step)
    },
    [aspect, still, view],
  )
  useEffect(() => stopAnim, [])

  const choosePreset = (p: MapPreset) => {
    setPreset(p)
    try {
      localStorage.setItem(PRESET_KEY, p)
    } catch {
      // Private mode: the choice just isn't remembered.
    }
    animateTo(fit(PRESETS[p], aspect))
  }
  const zoomBy = (factor: number, at?: { x: number; y: number }) => {
    stopAnim()
    setView((cur) => {
      const c = cur ?? v
      const upp = c.vw / size.w
      const px = at?.x ?? size.w / 2
      const py = at?.y ?? size.h / 2
      const mx = c.cx + (px - size.w / 2) * upp
      const my = c.cy + (py - size.h / 2) * upp
      const vw = c.vw * factor
      const upp2 = vw / size.w
      return clampView(
        { cx: mx - (px - size.w / 2) * upp2, cy: my - (py - size.h / 2) * upp2, vw },
        aspect,
      )
    })
  }
  const panBy = (dxPx: number, dyPx: number) => {
    stopAnim()
    setView((cur) => {
      const c = cur ?? v
      const upp = c.vw / size.w
      return clampView({ cx: c.cx - dxPx * upp, cy: c.cy - dyPx * upp, vw: c.vw }, aspect)
    })
  }

  // Wheel zoom needs a non-passive listener to keep the page still.
  const zoomRef = useRef(zoomBy)
  useEffect(() => {
    zoomRef.current = zoomBy
  })
  useEffect(() => {
    const el = hostRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      zoomRef.current(Math.exp(e.deltaY * 0.0016), { x: e.clientX - r.left, y: e.clientY - r.top })
    }
    el.addEventListener("wheel", onWheel, { passive: false })
    return () => el.removeEventListener("wheel", onWheel)
  }, [])

  // Drag to pan, two fingers to pinch.
  const pointers = useRef(new Map<number, { x: number; y: number }>())
  const moved = useRef(0)
  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY })
    moved.current = 0
  }
  const onPointerMove = (e: React.PointerEvent) => {
    const prev = pointers.current.get(e.pointerId)
    if (!prev) return
    const next = { x: e.clientX, y: e.clientY }
    if (pointers.current.size === 1) {
      const dx = next.x - prev.x
      const dy = next.y - prev.y
      moved.current += Math.abs(dx) + Math.abs(dy)
      if (moved.current > 4) {
        if (!hostRef.current?.hasPointerCapture(e.pointerId))
          hostRef.current?.setPointerCapture(e.pointerId)
        panBy(dx, dy)
      }
    } else if (pointers.current.size === 2) {
      const others = [...pointers.current.entries()].filter(([id]) => id !== e.pointerId)
      const other = others[0]?.[1]
      if (other) {
        const before = Math.hypot(prev.x - other.x, prev.y - other.y)
        const after = Math.hypot(next.x - other.x, next.y - other.y)
        const r = hostRef.current?.getBoundingClientRect()
        if (before > 0 && r) {
          moved.current += 10
          zoomBy(before / after, {
            x: (next.x + other.x) / 2 - r.left,
            y: (next.y + other.y) / 2 - r.top,
          })
        }
      }
    }
    pointers.current.set(e.pointerId, next)
  }
  const onPointerUp = (e: React.PointerEvent) => {
    pointers.current.delete(e.pointerId)
  }
  const onKeyDown = (e: React.KeyboardEvent) => {
    const step = 60
    const keys: Record<string, () => void> = {
      ArrowLeft: () => panBy(step, 0),
      ArrowRight: () => panBy(-step, 0),
      ArrowUp: () => panBy(0, step),
      ArrowDown: () => panBy(0, -step),
      "+": () => zoomBy(0.7),
      "=": () => zoomBy(0.7),
      "-": () => zoomBy(1 / 0.7),
      "0": () => choosePreset("world"),
      e: () => choosePreset("europe"),
    }
    const fn = keys[e.key]
    if (fn && e.target === e.currentTarget) {
      e.preventDefault()
      fn()
    }
  }

  // New events: one dash each along their source's arc (capped, calm).
  const [dashes, setDashes] = useState<Dash[]>([])
  const lastId = useRef<number | null>(null)
  useEffect(() => {
    const newest = events[0]?.id ?? 0
    if (lastId.current === null) {
      lastId.current = newest
      return
    }
    const since = lastId.current
    lastId.current = Math.max(since, newest)
    if (still || paused) return
    const fresh = events
      .filter((e) => e.id > since && e.country)
      .slice(0, 4)
      .flatMap((e) => {
        const src = activity.sources.find((s) => s.country === e.country?.toUpperCase())
        return src ? [{ key: e.id, country: src.country, family: src.family }] : []
      })
    if (!fresh.length) return
    setDashes((d) => [...d, ...fresh].slice(-MAX_DASHES))
    const t = setTimeout(
      () => setDashes((d) => d.filter((x) => !fresh.some((f) => f.key === x.key))),
      DASH_MS,
    )
    return () => clearTimeout(t)
  }, [events, still, paused, activity.sources])

  // Tooltip for a hovered or focused source.
  const [hover, setHover] = useState<string | null>(null)

  const homeXY = useMemo(() => project(home.lat, home.lon), [home.lat, home.lon])
  const upp = v.vw / size.w
  const vh = v.vw / aspect
  const toScreen = (p: [number, number]) => ({
    x: (p[0] - (v.cx - v.vw / 2)) / upp,
    y: (p[1] - (v.cy - vh / 2)) / upp,
  })

  const drawn = useMemo(
    () =>
      activity.sources
        .map((s) => {
          const xy = project(s.point.lat, s.point.lon)
          return { s, xy, d: arcPath(xy, homeXY) }
        })
        // Quietest first, so the busiest arcs and dots sit on top.
        .reverse(),
    [activity.sources, homeXY],
  )
  const hovered = drawn.find((x) => x.s.country === hover)

  const open = (s: Source) => void navigate(`/attacks?country=${s.country}`)

  return (
    <div
      ref={hostRef}
      className={cn(
        "relative size-full touch-pan-y overflow-hidden outline-none select-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset",
        className,
      )}
      tabIndex={0}
      role="group"
      aria-roledescription="map"
      aria-label={`Map of attack origins in the last 15 minutes, with arcs landing on ${homeLabel ?? "the sensors"}. Arrow keys pan, plus and minus zoom, E shows Europe, 0 the world.`}
      onKeyDown={onKeyDown}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
    >
      <svg
        className="absolute inset-0 size-full"
        viewBox={`${v.cx - v.vw / 2} ${v.cy - vh / 2} ${v.vw} ${vh}`}
        preserveAspectRatio="xMidYMid meet"
        aria-hidden
      >
        <path d={LAND_PATH} fill="var(--map-land)" fillRule="evenodd" />
        <path
          d={BORDERS_PATH}
          fill="none"
          stroke="var(--map-border)"
          strokeWidth={0.6}
          vectorEffect="non-scaling-stroke"
          strokeLinejoin="round"
        />

        {drawn.map(({ s, d }) =>
          d ? (
            <path
              key={`arc-${s.country}`}
              d={d}
              fill="none"
              stroke={FAMILY_META[s.family].cssVar}
              strokeOpacity={0.75 * ageOpacity(s.last, now)}
              strokeWidth={1 + 2.2 * countWeight(s.events)}
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          ) : null,
        )}

        {dashes.map((dash) => {
          const hit = drawn.find((x) => x.s.country === dash.country)
          if (!hit?.d) return null
          return (
            <path
              key={`dash-${dash.key}`}
              d={hit.d}
              pathLength={1}
              fill="none"
              stroke={FAMILY_META[hit.s.family].cssVar}
              strokeWidth={2.6}
              strokeLinecap="round"
              strokeDasharray="0.14 2"
              vectorEffect="non-scaling-stroke"
              className="animate-map-dash"
            />
          )
        })}

        {drawn.map(({ s, xy }) => {
          const r = (2.6 + 4.4 * countWeight(s.events)) * upp
          const active = !still && now - s.last < ACTIVE_MS
          const color = FAMILY_META[s.family].cssVar
          return (
            <g key={`src-${s.country}`}>
              {active ? (
                <circle
                  cx={xy[0]}
                  cy={xy[1]}
                  r={r}
                  fill="none"
                  stroke={color}
                  strokeWidth={1}
                  vectorEffect="non-scaling-stroke"
                  className="[transform-origin:center] animate-map-pulse [transform-box:fill-box]"
                />
              ) : null}
              <circle
                cx={xy[0]}
                cy={xy[1]}
                r={r}
                fill={color}
                fillOpacity={0.35 + 0.6 * ageOpacity(s.last, now)}
                stroke="var(--surface)"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
            </g>
          )
        })}

        {/* Home: a solid dot and a slow ring. */}
        {!still ? (
          <circle
            cx={homeXY[0]}
            cy={homeXY[1]}
            r={4 * upp}
            fill="none"
            stroke="var(--fg)"
            strokeWidth={1}
            vectorEffect="non-scaling-stroke"
            className="[transform-origin:center] animate-map-pulse [transform-box:fill-box]"
          />
        ) : null}
        <circle
          cx={homeXY[0]}
          cy={homeXY[1]}
          r={3.5 * upp}
          fill="var(--fg)"
          stroke="var(--surface)"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
        />
      </svg>

      {/* Hit targets for the sources: real buttons, so they are focusable and clickable. */}
      {drawn.map(({ s, xy }) => {
        const p = toScreen(xy)
        if (p.x < -10 || p.y < -10 || p.x > size.w + 10 || p.y > size.h + 10) return null
        const name = countryName(s.country) ?? s.country
        return (
          <button
            key={`hit-${s.country}`}
            type="button"
            className="absolute size-6 -translate-x-1/2 -translate-y-1/2 rounded-full outline-none focus-visible:ring-2 focus-visible:ring-ring"
            style={{ left: p.x, top: p.y }}
            aria-label={`${name}: ${plural(s.events, "event")} from ${plural(s.ips, "address", "addresses")}. Open these attacks.`}
            onPointerEnter={() => setHover(s.country)}
            onPointerLeave={() => setHover((h) => (h === s.country ? null : h))}
            onFocus={() => setHover(s.country)}
            onBlur={() => setHover((h) => (h === s.country ? null : h))}
            onClick={() => {
              if (moved.current <= 4) open(s)
            }}
          />
        )
      })}

      {/* Labels for the busiest visible sources, skipped where they would collide. */}
      {(() => {
        const placed: { x0: number; y0: number; x1: number; y1: number }[] = []
        const home = toScreen(homeXY)
        placed.push({ x0: home.x - 8, y0: home.y - 8, x1: home.x + 8, y1: home.y + 8 })
        return activity.sources.slice(0, 10).flatMap((s) => {
          const xy = project(s.point.lat, s.point.lon)
          const p = toScreen(xy)
          const text = `${s.country} ${formatNumber(s.events)}`
          const w = 8 + text.length * 6.2
          const r = 2.6 + 4.4 * countWeight(s.events)
          const box = { x0: p.x + r + 3, y0: p.y - 8, x1: p.x + r + 3 + w, y1: p.y + 8 }
          if (box.x0 < 0 || box.y0 < 44 || box.x1 > size.w - 4 || box.y1 > size.h - 4) return []
          if (placed.some((b) => b.x0 < box.x1 && box.x0 < b.x1 && b.y0 < box.y1 && box.y0 < b.y1))
            return []
          placed.push(box)
          return [
            <span
              key={`label-${s.country}`}
              aria-hidden
              className="pointer-events-none absolute flex h-4 items-center rounded-xs bg-surface/80 px-1 font-mono text-2xs text-fg-muted"
              style={{ left: box.x0, top: box.y0 }}
            >
              <span className="text-fg">{s.country}</span>&nbsp;{formatNumber(s.events)}
            </span>,
          ]
        })
      })()}

      {hovered ? (
        <SourceTooltip source={hovered.s} at={toScreen(hovered.xy)} width={size.w} />
      ) : null}

      <div className="absolute top-3 right-3 flex items-center gap-1">
        <div className="flex rounded-md border bg-surface-raised/90 p-0.5 shadow-sm backdrop-blur-sm">
          {(["europe", "world"] as const).map((p) => (
            <button
              key={p}
              type="button"
              aria-pressed={preset === p}
              onClick={() => choosePreset(p)}
              className={cn(
                "h-6 rounded-sm px-2 text-xs font-medium transition-colors",
                preset === p ? "bg-surface-hover text-fg" : "text-fg-muted hover:text-fg",
              )}
            >
              {p === "europe" ? "Europe" : "World"}
            </button>
          ))}
        </div>
        <div className="flex rounded-md border bg-surface-raised/90 p-0.5 shadow-sm backdrop-blur-sm">
          <button
            type="button"
            aria-label="Zoom in"
            onClick={() => zoomBy(0.7)}
            className="flex size-6 items-center justify-center rounded-sm text-fg-muted hover:text-fg"
          >
            <Plus aria-hidden className="size-3.5" />
          </button>
          <button
            type="button"
            aria-label="Zoom out"
            onClick={() => zoomBy(1 / 0.7)}
            className="flex size-6 items-center justify-center rounded-sm text-fg-muted hover:text-fg"
          >
            <Minus aria-hidden className="size-3.5" />
          </button>
        </div>
      </div>
    </div>
  )
}

function SourceTooltip({
  source,
  at,
  width,
}: {
  source: Source
  at: { x: number; y: number }
  width: number
}) {
  const name = countryName(source.country) ?? source.country
  const left = Math.min(Math.max(8, at.x + 12), width - 228)
  return (
    <div
      role="tooltip"
      className="pointer-events-none absolute z-10 w-55 animate-fade-in rounded-md border bg-surface-raised p-3 text-xs shadow-md"
      style={{ left, top: Math.max(8, at.y - 12) }}
    >
      <p className="font-medium text-fg">{name}</p>
      <p className="mt-1 text-fg-muted">
        <span className="font-medium text-fg tabular-nums">{formatNumber(source.events)}</span>{" "}
        {source.events === 1 ? "event" : "events"} from{" "}
        <span className="font-medium text-fg tabular-nums">{formatNumber(source.ips)}</span>{" "}
        {source.ips === 1 ? "address" : "addresses"}
      </p>
      <p className="mt-1.5 flex flex-wrap gap-x-2 gap-y-1 text-fg-muted">
        {source.sensors.map((s) => {
          const m = SENSOR_META[s]
          return (
            <span key={s} className="inline-flex items-center gap-1">
              <m.icon aria-hidden className={cn("size-3", m.text)} />
              {m.label}
            </span>
          )
        })}
      </p>
      <p className="mt-1.5 text-fg-subtle">Click to open these attacks</p>
    </div>
  )
}
