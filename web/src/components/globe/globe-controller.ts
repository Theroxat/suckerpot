import Globe, { type GlobeInstance } from "globe.gl"
import { MeshBasicMaterial } from "three"
import type { LiveEvent } from "@/lib/api"
import { ArcQueue, latestDistinctArcs, newArcs, type Arc } from "./arc-queue"
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
/** Arcs shown at once in the static (reduced motion) view. */
const STATIC_ARCS = 9
/** Rotation resumes this long after the last touch or drag. */
const RESUME_ROTATION_MS = 8_000
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
/** Arcs from the first backfill are staggered so the globe fills in calmly. */
const INTRO_ARCS = 10
const INTRO_STEP_MS = 280
/** A burst of events is spread out over this step, ms, and capped. */
const BURST_STEP_MS = 220
const BURST_MAX = 12

interface RingDatum {
  lat: number
  lng: number
  color: string
}

interface PointDatum {
  lat: number
  lng: number
  r: number
  home?: boolean
}

/**
 * Camera framing: look at the home point from slightly north-east of it. Most attacks come
 * from the east (Russia, China, South-East Asia), so their arcs then run across the visible
 * face of the sphere instead of climbing over its top edge, where they read as spikes.
 */
function viewFor(home: GeoPoint) {
  return { lat: Math.min(60, home.lat + 6), lng: home.lon + 35, altitude: 1.75 }
}

type DestructibleGlobe = GlobeInstance & { _destructor: () => void }

function hueOf(p: GlobePalette, sensor: string): string {
  return (p.sensors as Record<string, string | undefined>)[sensor] ?? p.land
}

/**
 * Owns the globe.gl instance and everything that moves on it. Free of React so the component
 * stays a thin shell. Calm by design: a flat sphere with land dots, thin arcs in the sensor
 * hue that fly once and vanish, a soft ring where they land.
 */
export class GlobeController {
  private globe: DestructibleGlobe
  private palette: GlobePalette
  private home: GeoPoint
  private readonly queue = new ArcQueue()
  private rings: RingDatum[] = []
  private readonly timers = new Set<ReturnType<typeof setTimeout>>()
  private lastId: number | null = null
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
      .arcStroke(0.3)
      .arcAltitude((d) => arcAltitude((d as Arc).from, (d as Arc).to))
      .arcCurveResolution(48)
      .arcStartLat((d) => (d as Arc).from.lat)
      .arcStartLng((d) => (d as Arc).from.lon)
      .arcEndLat((d) => (d as Arc).to.lat)
      .arcEndLng((d) => (d as Arc).to.lon)
      .arcColor((d: object) => {
        const hue = hueOf(this.palette, (d as Arc).sensor)
        return [withAlpha(hue, 0.1), withAlpha(hue, 0.9)]
      })
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
      .pointOfView(viewFor(home))

    if (reduced) globe.arcDashLength(1).arcDashGap(0).arcDashAnimateTime(0)
    else {
      globe
        .arcDashLength(DASH_LENGTH)
        .arcDashGap(DASH_GAP)
        .arcDashInitialGap((d: object) => (this.shown.has(d) ? 0 : 2))
        .arcDashAnimateTime(DASH_ANIMATE_MS)
    }

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
    controls.autoRotateSpeed = 0.3
    controls.autoRotate = !this.reduced && !frozen
    // Reduced motion and the test hook keep the view still: no drag either.
    const interactive = !this.reduced && !frozen
    controls.enableRotate = interactive
    this.globe.enablePointerInteraction(interactive)
    if (!interactive) return
    let resume: ReturnType<typeof setTimeout> | undefined
    const onStart = () => {
      controls.autoRotate = false
      clearTimeout(resume)
    }
    const onEnd = () => {
      clearTimeout(resume)
      resume = setTimeout(() => {
        controls.autoRotate = true
      }, RESUME_ROTATION_MS)
    }
    controls.addEventListener("start", onStart)
    controls.addEventListener("end", onEnd)
    this.cleanups.push(() => {
      clearTimeout(resume)
      controls.removeEventListener("start", onStart)
      controls.removeEventListener("end", onEnd)
    })
  }

  private setupSizing(host: HTMLElement) {
    const size = () => {
      const { clientWidth: w, clientHeight: h } = host
      if (w > 0 && h > 0) this.globe.width(w).height(h)
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
    this.globe.arcsData([...this.queue.arcs])
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
    this.globe.pointOfView(viewFor(home))
    this.drawPoints()
  }

  /** `events` is newest first. Call whenever the feed changes. */
  feed(events: readonly LiveEvent[], paused: boolean) {
    const frozen = globeFrozen()
    if (this.reduced) {
      // Static view: the latest distinct origins, no motion at all.
      if (frozen && this.lastId !== null) return
      const arcs = latestDistinctArcs(events, this.home, STATIC_ARCS * 2)
        .filter((a) => drawableArc(a.from, a.to))
        .slice(0, STATIC_ARCS)
      if (arcs.length === 0) return
      this.lastId = events[0]?.id ?? 0
      this.queue.clear()
      arcs.reverse().forEach((a) => this.queue.add(a))
      this.pushArcs()
      return
    }
    if (this.lastId === null) {
      if (events.length === 0) return
      this.lastId = events[0]?.id ?? 0
      latestDistinctArcs(events, this.home, INTRO_ARCS)
        .reverse()
        .forEach((a, i) => this.later(() => this.launch(a), i * INTRO_STEP_MS))
      return
    }
    if (frozen) return
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
