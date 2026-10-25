import Globe, { type GlobeInstance } from "globe.gl"
import { MeshBasicMaterial } from "three"
import type { LiveEvent } from "@/lib/api"
import { familyOf } from "@/lib/sensors"
import { ageOpacity, countWeight, type Source } from "@/components/map/activity"
import { ArcQueue, newArcs, type Arc } from "./arc-queue"
import { landDots } from "./data/land-dots"
import { arcAltitude, drawableArc, type GeoPoint } from "./geo"
import {
  globeFrozen,
  prefersReducedMotion,
  readPalette,
  withAlpha,
  type GlobePalette,
} from "./palette"

/** Cap on the render resolution: a retina screen would otherwise draw 4x the pixels. */
const MAX_PIXEL_RATIO = 1.5
/**
 * three-globe animates a dash by sliding a pattern along the arc, and a fresh arc always starts
 * with the dash parked at its far end. The arc stays hidden for this long (the time the parked
 * dash needs to slide out of view), then the comet flies from the source to the target.
 */
const HIDDEN_MS = 640
/** The comet reaches the target this long after the arc was added, ms. */
const LANDING_MS = 2_000
const DASH_LENGTH = 0.4
const DASH_GAP = 1
const DASH_ANIMATE_MS = 1_600
const RING_MS = 2_200
const MAX_RINGS = 12
/** A burst of events is spread out over this step, ms, and capped. */
const BURST_STEP_MS = 220
const BURST_MAX = 12

interface RingDatum {
  lat: number
  lng: number
  color: string
}

/** A persistent arc for one recent source country (the calm "last 15 minutes" picture). */
interface StaticArc {
  static: true
  from: GeoPoint
  to: GeoPoint
  color: string
  opacity: number
  weight: number
}

interface SourceLabel {
  lat: number
  lng: number
  text: string
  color: string
  weight: number
}

type ArcDatum = Arc | StaticArc
const isStatic = (d: object): d is StaticArc => "static" in d

interface PointDatum {
  lat: number
  lng: number
  r: number
  home?: boolean
}

/**
 * Camera framing: Europe in the middle, home slightly off-centre, so the short arcs from
 * neighbouring countries (the most common real attackers) are seen face-on and readable.
 */
function viewFor(home: GeoPoint, altitude: number) {
  return { lat: Math.min(60, home.lat + 2), lng: home.lon + 6, altitude }
}

/** Default vertical field of view of the globe.gl camera, degrees. */
const FOV = 50

/** Camera altitude that keeps the whole sphere inside a w x h card, with a margin. */
export function fitAltitude(w: number, h: number, margin = 0.86): number {
  const halfV = ((FOV / 2) * Math.PI) / 180
  const halfH = Math.atan(Math.tan(halfV) * (w / Math.max(1, h)))
  const half = Math.min(halfV, halfH) * margin
  return Math.max(1.2, 1 / Math.sin(half) - 1)
}

type DestructibleGlobe = GlobeInstance & { _destructor: () => void }

function hueOf(p: GlobePalette, sensor: string): string {
  const family = familyOf(sensor)
  return family ? p.families[family] : p.land
}

/**
 * Owns the globe.gl instance and everything that moves on it. Free of React so the component
 * stays a thin shell. Calm by design: a flat sphere with land dots, thin arcs in the sensor
 * family hue that fly once and vanish, a soft ring where they land.
 */
export class GlobeController {
  private globe: DestructibleGlobe
  private palette: GlobePalette
  private home: GeoPoint
  private readonly queue = new ArcQueue()
  private rings: RingDatum[] = []
  private readonly timers = new Set<ReturnType<typeof setTimeout>>()
  private lastId: number | null = null
  private staticArcs: StaticArc[] = []
  private altitude = 1.75
  /** Arcs whose comet is flying. Others are still waiting for the parked dash to clear. */
  private readonly shown = new WeakSet<object>()
  private readonly reduced = prefersReducedMotion()
  private readonly cleanups: (() => void)[] = []

  /** Throws when WebGL is unavailable. */
  constructor(host: HTMLElement, home: GeoPoint) {
    this.home = home
    const reduced = this.reduced
    const globe: DestructibleGlobe = new Globe(host, {
      rendererConfig: { antialias: true, alpha: true, powerPreference: "low-power" },
      animateIn: false,
      waitForGlobeReady: false,
    })
    this.globe = globe
    this.palette = readPalette()

    globe
      .backgroundColor("rgba(0,0,0,0)")
      .showGlobe(true)
      .showAtmosphere(true)
      .atmosphereAltitude(0.14)
      .showGraticules(false)
      .pointsMerge(true)
      .pointResolution(5)
      .pointColor((d) =>
        (d as PointDatum).home ? this.palette.home : withAlpha(this.palette.land, 0.5),
      )
      .pointRadius((d) => (d as PointDatum).r)
      .pointAltitude((d) => ((d as PointDatum).home ? 0.006 : 0.001))
      .arcStroke((d: object) => (isStatic(d) ? 0.12 + 0.45 * d.weight : 0.32))
      .arcAltitude((d) => arcAltitude((d as ArcDatum).from, (d as ArcDatum).to))
      .arcCurveResolution(48)
      .arcStartLat((d) => (d as ArcDatum).from.lat)
      .arcStartLng((d) => (d as ArcDatum).from.lon)
      .arcEndLat((d) => (d as ArcDatum).to.lat)
      .arcEndLng((d) => (d as ArcDatum).to.lon)
      .arcColor((d: object) => {
        if (isStatic(d))
          return [withAlpha(d.color, 0.25 * d.opacity), withAlpha(d.color, 0.8 * d.opacity)]
        const hue = hueOf(this.palette, (d as Arc).sensor)
        return [withAlpha(hue, 0.1), withAlpha(hue, 0.95)]
      })
      .labelLat((d) => (d as SourceLabel).lat)
      .labelLng((d) => (d as SourceLabel).lng)
      .labelText((d) => (d as SourceLabel).text)
      .labelColor((d) => (d as SourceLabel).color)
      .labelSize(0.9)
      .labelDotRadius((d) => 0.35 + 0.65 * (d as SourceLabel).weight)
      .labelIncludeDot(true)
      .labelDotOrientation(() => "right")
      .labelAltitude(0.002)
      .labelResolution(2)
      .arcsTransitionDuration(0)
      .ringLat((d) => (d as RingDatum).lat)
      .ringLng((d) => (d as RingDatum).lng)
      .ringColor((d: object) => {
        const c = (d as RingDatum).color
        return (t: number) => withAlpha(c, 0.55 * (1 - t))
      })
      .ringMaxRadius(5)
      .ringPropagationSpeed(2.2)
      .ringRepeatPeriod(0)
      .pointOfView(viewFor(home, this.altitude))

    // Persistent arcs are solid lines; only the comet of a new event animates.
    globe
      .arcDashLength((d: object) => (isStatic(d) ? 1 : DASH_LENGTH))
      .arcDashGap((d: object) => (isStatic(d) ? 0 : DASH_GAP))
      .arcDashInitialGap((d: object) => (isStatic(d) || this.shown.has(d) ? 0 : 2))
      .arcDashAnimateTime((d: object) => (isStatic(d) || reduced ? 0 : DASH_ANIMATE_MS))

    globe.renderer().setPixelRatio(Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO))
    // Vertical swipes scroll the page; horizontal drags turn the globe.
    globe.renderer().domElement.style.touchAction = "pan-y"
    this.applyPalette()
    this.setupControls()
    this.setupSizing(host)
    this.setupVisibility(host)
    this.setupTheme()

    if (!reduced) {
      const sweep = setInterval(() => {
        if (this.queue.prune(Date.now())) this.pushArcs()
      }, 150)
      this.cleanups.push(() => clearInterval(sweep))
    }
  }

  // --- Setup --------------------------------------------------------------

  private setupControls() {
    const controls = this.globe.controls()
    const frozen = globeFrozen()
    controls.enableZoom = false
    controls.enablePan = false
    // No auto-rotation: Europe stays in view so short arcs are readable at a glance.
    controls.autoRotate = false
    // The test hook keeps the view still: no drag either.
    const interactive = !frozen
    controls.enableRotate = interactive
    this.globe.enablePointerInteraction(interactive)
  }

  private setupSizing(host: HTMLElement) {
    const size = () => {
      const { clientWidth: w, clientHeight: h } = host
      if (w > 0 && h > 0) {
        this.globe.width(w).height(h)
        // Fit the whole sphere to the card, whatever its shape (1440 or 1920 wide, phone).
        const alt = fitAltitude(w, h)
        if (Math.abs(alt - this.altitude) > 0.01) {
          this.altitude = alt
          this.globe.pointOfView(viewFor(this.home, alt), 0)
        }
      }
    }
    size()
    const ro = new ResizeObserver(size)
    ro.observe(host)
    this.cleanups.push(() => ro.disconnect())
  }

  /** Nothing is drawn while the tab is hidden or the globe is scrolled out of view. */
  private setupVisibility(host: HTMLElement) {
    let hidden = document.visibilityState === "hidden"
    let offscreen = false
    const sync = () => {
      if (hidden || offscreen) this.globe.pauseAnimation()
      else this.globe.resumeAnimation()
    }
    const onVisibility = () => {
      hidden = document.visibilityState === "hidden"
      sync()
    }
    document.addEventListener("visibilitychange", onVisibility)
    const io = new IntersectionObserver((entries) => {
      offscreen = !(entries[entries.length - 1]?.isIntersecting ?? true)
      sync()
    })
    io.observe(host)
    this.cleanups.push(() => {
      document.removeEventListener("visibilitychange", onVisibility)
      io.disconnect()
    })
    sync()
  }

  private setupTheme() {
    const retheme = () => {
      this.palette = readPalette()
      this.applyPalette()
    }
    const mo = new MutationObserver(retheme)
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] })
    const mq = window.matchMedia("(prefers-color-scheme: dark)")
    mq.addEventListener("change", retheme)
    this.cleanups.push(() => {
      mo.disconnect()
      mq.removeEventListener("change", retheme)
    })
  }

  // --- Drawing ------------------------------------------------------------

  private applyPalette() {
    const p = this.palette
    this.globe.globeMaterial(new MeshBasicMaterial({ color: p.sphere }))
    this.globe.atmosphereColor(p.rim)
    this.drawPoints()
  }

  private drawPoints() {
    const dots = landDots()
    const points: PointDatum[] = []
    for (let i = 0; i < dots.length; i += 2) {
      points.push({ lat: dots[i] ?? 0, lng: dots[i + 1] ?? 0, r: 0.5 })
    }
    points.push({ lat: this.home.lat, lng: this.home.lon, r: 1.1, home: true })
    this.globe.pointsData(points)
  }

  private pushArcs() {
    this.globe.arcsData([...this.staticArcs, ...this.queue.arcs])
  }

  private pushRings() {
    this.globe.ringsData([...this.rings])
  }

  private later(fn: () => void, ms: number) {
    const t = setTimeout(() => {
      this.timers.delete(t)
      fn()
    }, ms)
    this.timers.add(t)
  }

  /** A ring where an attack lands (or, for a degenerate arc, the only mark it leaves). */
  private pulse(arc: Arc) {
    const ring: RingDatum = {
      lat: arc.to.lat,
      lng: arc.to.lon,
      color: hueOf(this.palette, arc.sensor),
    }
    this.rings = [...this.rings, ring].slice(-MAX_RINGS)
    this.pushRings()
    this.later(() => {
      this.rings = this.rings.filter((r) => r !== ring)
      this.pushRings()
    }, RING_MS)
  }

  private launch(arc: Arc) {
    if (!drawableArc(arc.from, arc.to)) {
      // Too short (same country as home) or antipodal: no arc, just a ring pulse.
      this.pulse(arc)
      return
    }
    const flying = { ...arc, born: Date.now() }
    this.queue.add(flying)
    this.pushArcs()
    this.later(() => {
      this.shown.add(flying)
      this.pushArcs()
    }, HIDDEN_MS)
    this.later(() => this.pulse(arc), LANDING_MS)
  }

  // --- Input --------------------------------------------------------------

  setHome(home: GeoPoint) {
    if (home.lat === this.home.lat && home.lon === this.home.lon) return
    this.home = home
    this.globe.pointOfView(viewFor(home, this.altitude))
    this.drawPoints()
  }

  /** The persistent picture: one arc and one labelled dot per recent source country. */
  setSources(sources: readonly Source[], now: number) {
    const p = this.palette
    this.staticArcs = sources
      .filter((src) => drawableArc(src.point, this.home))
      .map((src) => ({
        static: true as const,
        from: src.point,
        to: this.home,
        color: p.families[src.family],
        opacity: ageOpacity(src.last, now),
        weight: countWeight(src.events),
      }))
    const labels: SourceLabel[] = sources.map((src) => ({
      lat: src.point.lat,
      lng: src.point.lon,
      text: src.country,
      color: withAlpha(p.families[src.family], 0.4 + 0.6 * ageOpacity(src.last, now)),
      weight: countWeight(src.events),
    }))
    this.globe.labelsData(labels)
    this.pushArcs()
  }

  /** `events` is newest first. New events (after the first call) fly a comet along their arc. */
  feed(events: readonly LiveEvent[], paused: boolean) {
    if (this.lastId === null) {
      this.lastId = events[0]?.id ?? 0
      return
    }
    if (this.reduced || globeFrozen()) {
      this.lastId = Math.max(this.lastId, events[0]?.id ?? 0)
      return
    }
    const { arcs, lastId } = newArcs(events, this.lastId, this.home, Date.now())
    this.lastId = lastId
    if (paused) return
    arcs.slice(-BURST_MAX).forEach((a, i) => this.later(() => this.launch(a), i * BURST_STEP_MS))
  }

  destroy() {
    this.cleanups.forEach((fn) => fn())
    this.cleanups.length = 0
    this.timers.forEach(clearTimeout)
    this.timers.clear()
    this.queue.clear()
    try {
      this.globe.pauseAnimation()
      this.globe._destructor()
      this.globe.renderer().dispose()
    } catch {
      // Already torn down.
    }
  }
}
