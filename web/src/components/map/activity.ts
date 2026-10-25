/**
 * The picture the Live map draws: recent attack sources, aggregated per
 * country, so the view stays a calm, persistent summary of the last few
 * minutes instead of flashes that vanish. Also the "top attackers right now"
 * rankings (addresses, networks) shown under the map. Pure: events in, ranks out.
 */
import type { LiveEvent } from "@/lib/api"
import { SENSOR_META, SENSORS, isSensor, type Sensor, type SensorFamily } from "@/lib/sensors"
import { COUNTRY_CENTROIDS } from "./data/centroids"

export interface GeoPoint {
  lat: number
  lon: number
}

/** How far back the picture reaches. */
export const ACTIVITY_WINDOW_MS = 15 * 60_000
/** At most this many sources (arcs) at once. */
export const MAX_SOURCES = 60
/** A source counts as "active" (pulsing) this long after its last event. */
export const ACTIVE_MS = 60_000

export interface Source {
  /** ISO country code (the aggregation key). */
  country: string
  point: GeoPoint
  events: number
  ips: number
  /** The busiest address of this country, for the tooltip. */
  topIp: string
  /** Distinct sensors hit, in registry order. */
  sensors: Sensor[]
  /** The family with the most events: the arc and dot colour. */
  family: SensorFamily
  /** Newest event time, ms. */
  last: number
  /** Newest event id. */
  lastId: number
}

export interface Activity {
  /** Busiest first. */
  sources: Source[]
  /** Events in the window. */
  events: number
  /** Events in the window with no known country (not drawable). */
  unlocated: number
}

/** `events` newest first (the live buffer). */
export function aggregateSources(
  events: readonly LiveEvent[],
  now: number,
  windowMs = ACTIVITY_WINDOW_MS,
  limit = MAX_SOURCES,
): Activity {
  interface Acc {
    country: string
    events: number
    ips: Map<string, number>
    sensors: Map<string, number>
    last: number
    lastId: number
  }
  const byCountry = new Map<string, Acc>()
  let total = 0
  let unlocated = 0
  for (const e of events) {
    const ts = Date.parse(e.ts)
    if (!(now - ts <= windowMs)) continue
    total += 1
    const country = e.country?.toUpperCase()
    if (!country || !(country in COUNTRY_CENTROIDS)) {
      unlocated += 1
      continue
    }
    let a = byCountry.get(country)
    if (!a) {
      a = { country, events: 0, ips: new Map(), sensors: new Map(), last: ts, lastId: e.id }
      byCountry.set(country, a)
    }
    a.events += 1
    a.ips.set(e.src_ip, (a.ips.get(e.src_ip) ?? 0) + 1)
    a.sensors.set(e.sensor, (a.sensors.get(e.sensor) ?? 0) + 1)
    if (ts > a.last) a.last = ts
    if (e.id > a.lastId) a.lastId = e.id
  }

  const sources: Source[] = []
  for (const a of byCountry.values()) {
    const c = COUNTRY_CENTROIDS[a.country]
    if (!c) continue
    const { sensors, family } = sensorsAndFamily(a.sensors)
    const topIp = [...a.ips.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] ?? ""
    sources.push({
      country: a.country,
      point: { lat: c[0], lon: c[1] },
      events: a.events,
      ips: a.ips.size,
      topIp,
      sensors,
      family,
      last: a.last,
      lastId: a.lastId,
    })
  }
  sources.sort((x, y) => y.events - x.events || y.last - x.last)
  return { sources: sources.slice(0, limit), events: total, unlocated }
}

/** Opacity from age: fresh sources are bright, they fade over the window but never vanish. */
export function ageOpacity(last: number, now: number, windowMs = ACTIVITY_WINDOW_MS): number {
  const age = Math.max(0, now - last) / windowMs
  return Math.max(0.22, Math.min(1, 1 - 0.78 * age))
}

/** Weight 0..1 from the event count (log scale: 1 event is thin, 100+ is the thickest). */
export function countWeight(events: number): number {
  return Math.min(1, Math.log10(Math.max(1, events)) / 2)
}

/** Distinct sensors of a count map, in registry order, plus the dominant family. */
function sensorsAndFamily(counts: ReadonlyMap<string, number>): {
  sensors: Sensor[]
  family: SensorFamily
} {
  const families = new Map<SensorFamily, number>()
  for (const [s, n] of counts) {
    if (isSensor(s)) {
      const f = SENSOR_META[s].family
      families.set(f, (families.get(f) ?? 0) + n)
    }
  }
  const family = [...families.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] ?? "shell"
  return { sensors: SENSORS.filter((s) => counts.has(s)), family }
}

export interface Leader {
  /** The address, or the AS number as a string. */
  key: string
  events: number
  /** Share of every event in the window, 0..1. */
  share: number
  /** Most frequent country (upper case), if known. */
  country: string | null
  /** Network name, if known. */
  org: string | null
  asn: number | null
  /** Distinct addresses (networks only; 1 for an address). */
  ips: number
  sensors: Sensor[]
  family: SensorFamily
  /** Newest event time, ms. */
  last: number
}

export interface Leaders {
  addresses: Leader[]
  networks: Leader[]
  /** Events in the window. */
  events: number
}

/** The busiest addresses and networks (AS numbers) of the window, `events` newest first. */
export function rankLeaders(
  events: readonly LiveEvent[],
  now: number,
  windowMs = ACTIVITY_WINDOW_MS,
  limit = 8,
): Leaders {
  interface Acc {
    key: string
    events: number
    countries: Map<string, number>
    org: string | null
    asn: number | null
    ips: Set<string>
    sensors: Map<string, number>
    last: number
  }
  const byIp = new Map<string, Acc>()
  const byAsn = new Map<string, Acc>()
  let total = 0
  const add = (map: Map<string, Acc>, key: string, e: LiveEvent, ts: number) => {
    let a = map.get(key)
    if (!a) {
      a = {
        key,
        events: 0,
        countries: new Map(),
        org: null,
        asn: null,
        ips: new Set(),
        sensors: new Map(),
        last: ts,
      }
      map.set(key, a)
    }
    a.events += 1
    const c = e.country?.toUpperCase()
    if (c) a.countries.set(c, (a.countries.get(c) ?? 0) + 1)
    a.org ??= e.org ?? null
    a.asn ??= e.asn ?? null
    a.ips.add(e.src_ip)
    a.sensors.set(e.sensor, (a.sensors.get(e.sensor) ?? 0) + 1)
    if (ts > a.last) a.last = ts
  }
  for (const e of events) {
    const ts = Date.parse(e.ts)
    if (!(now - ts <= windowMs)) continue
    total += 1
    add(byIp, e.src_ip, e, ts)
    if (e.asn != null) add(byAsn, String(e.asn), e, ts)
  }
  const finish = (map: Map<string, Acc>): Leader[] =>
    [...map.values()]
      .sort((x, y) => y.events - x.events || y.last - x.last)
      .slice(0, limit)
      .map((a) => ({
        key: a.key,
        events: a.events,
        share: total ? a.events / total : 0,
        country: [...a.countries.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] ?? null,
        org: a.org,
        asn: a.asn,
        ips: a.ips.size,
        ...sensorsAndFamily(a.sensors),
        last: a.last,
      }))
  return { addresses: finish(byIp), networks: finish(byAsn), events: total }
}

/**
 * Test hook: a Playwright init script sets `window.__SUCKERPOT_MAP__ = { freeze: true }`
 * so screenshots are deterministic (no dashes, pulses or slides).
 */
export function motionFrozen(): boolean {
  return (
    typeof window !== "undefined" &&
    (window as unknown as { __SUCKERPOT_MAP__?: { freeze?: boolean } }).__SUCKERPOT_MAP__
      ?.freeze === true
  )
}
