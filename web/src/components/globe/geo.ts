import { COUNTRY_CENTROIDS } from "./data/centroids"

export interface GeoPoint {
  lat: number
  lon: number
}

/** FNV-1a, 32 bit. Stable across runs, so the same address always lands on the same spot. */
export function hashString(value: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < value.length; i++) {
    h ^= value.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

/** Largest offset, in degrees of arc, from the country centre. */
export const JITTER_DEGREES = 2.4

/**
 * Where an attack from `country` starts on the globe: the country centre plus a small
 * offset derived from the address, so several sources in one country do not stack
 * into a single line. Null when the country is unknown.
 */
export function sourcePoint(country: string | null, ip: string): GeoPoint | null {
  if (!country) return null
  const centre = COUNTRY_CENTROIDS[country.toUpperCase()]
  if (!centre) return null
  const h = hashString(ip)
  // Two independent fractions in [-1, 1) from the low and high halves of the hash.
  const a = ((h & 0xffff) / 0x8000 - 1) * JITTER_DEGREES
  const b = ((h >>> 16) / 0x8000 - 1) * JITTER_DEGREES
  const lat = Math.max(-80, Math.min(80, centre[0] + a))
  const cos = Math.max(0.25, Math.cos((lat * Math.PI) / 180))
  let lon = centre[1] + b / cos
  if (lon > 180) lon -= 360
  if (lon < -180) lon += 360
  return { lat: Math.round(lat * 100) / 100, lon: Math.round(lon * 100) / 100 }
}

export function hasCentroid(country: string | null): boolean {
  return !!country && country.toUpperCase() in COUNTRY_CENTROIDS
}

/** Great-circle distance between two points, in degrees of arc (0..180). */
export function greatCircleDegrees(a: GeoPoint, b: GeoPoint): number {
  const rad = Math.PI / 180
  const dLat = (b.lat - a.lat) * rad
  const dLon = (b.lon - a.lon) * rad
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(a.lat * rad) * Math.cos(b.lat * rad) * Math.sin(dLon / 2) ** 2
  return (2 * Math.asin(Math.min(1, Math.sqrt(h)))) / rad
}

/**
 * Below this distance an arc degenerates (start and end nearly equal, e.g. an attack from the
 * home country): the interpolated curve shoots straight up. Such arrivals get a ring pulse only.
 * Near-antipodal pairs have no unique great circle and are skipped the same way.
 */
export const MIN_ARC_DEGREES = 4
export const MAX_ARC_DEGREES = 175

export function drawableArc(from: GeoPoint, to: GeoPoint): boolean {
  const d = greatCircleDegrees(from, to)
  return d >= MIN_ARC_DEGREES && d <= MAX_ARC_DEGREES
}

/** Arc height (in globe radii), proportional to distance and clamped so nothing spikes. */
export function arcAltitude(from: GeoPoint, to: GeoPoint): number {
  const d = greatCircleDegrees(from, to)
  // Kept low: arcs to the far side climb over the limb, and a tall arc reads as a spike there.
  return Math.min(0.18, Math.max(0.04, (d / 180) * 0.3))
}
