import type { LiveEvent } from "@/lib/api"
import { sourcePoint, type GeoPoint } from "./geo"

export interface Arc {
  /** Id of the event that produced the arc. */
  id: number
  sensor: string
  from: GeoPoint
  to: GeoPoint
  /** Creation time, ms. */
  born: number
}

/** Concurrent arcs on screen. The oldest are dropped first. */
export const MAX_ARCS = 60
/** How long a flying arc stays, ms. */
export const ARC_LIFETIME_MS = 2_200

/** A bounded list of arcs that drops the oldest on overflow and expires by age. */
export class ArcQueue {
  private items: Arc[] = []

  constructor(
    private readonly max = MAX_ARCS,
    private readonly lifetimeMs = ARC_LIFETIME_MS,
  ) {}

  add(arc: Arc): void {
    this.items.push(arc)
    if (this.items.length > this.max) this.items.splice(0, this.items.length - this.max)
  }

  /** Removes expired arcs. Returns true when something was removed. */
  prune(now: number): boolean {
    const before = this.items.length
    this.items = this.items.filter((a) => now - a.born < this.lifetimeMs)
    return this.items.length !== before
  }

  clear(): void {
    this.items = []
  }

  get arcs(): readonly Arc[] {
    return this.items
  }

  get size(): number {
    return this.items.length
  }
}

/**
 * Turns the events newer than `lastId` into arcs towards `home`, oldest first.
 * Events from unknown countries are skipped. `events` is newest first.
 */
export function newArcs(
  events: readonly LiveEvent[],
  lastId: number,
  home: GeoPoint,
  now: number,
): { arcs: Arc[]; lastId: number } {
  const arcs: Arc[] = []
  let newest = lastId
  for (const e of events) {
    if (e.id <= lastId) continue
    newest = Math.max(newest, e.id)
    const from = sourcePoint(e.country, e.src_ip)
    if (from) arcs.push({ id: e.id, sensor: e.sensor, from, to: home, born: now })
  }
  arcs.reverse()
  return { arcs, lastId: newest }
}

/** One arc per distinct source address, newest first, for the static (reduced motion) view. */
export function latestDistinctArcs(
  events: readonly LiveEvent[],
  home: GeoPoint,
  limit: number,
): Arc[] {
  const seen = new Set<string>()
  const out: Arc[] = []
  for (const e of events) {
    if (out.length >= limit) break
    if (seen.has(e.src_ip)) continue
    const from = sourcePoint(e.country, e.src_ip)
    if (!from) continue
    seen.add(e.src_ip)
    out.push({ id: e.id, sensor: e.sensor, from, to: home, born: 0 })
  }
  return out
}
