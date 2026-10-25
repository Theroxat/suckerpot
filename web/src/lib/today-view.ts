/** Small pure helpers behind the Today cards (kept apart from the components for unit tests). */
import { countryName, maskIpsInText } from "./format"
import type { TodayItem } from "./today"

/** The words shown for an item. Country codes become names; addresses are masked on request. */
export function itemLabel(item: TodayItem, masked: boolean): string {
  let label = item.label
  if (item.kind === "country") {
    const name = countryName(item.value)
    if (name) label = label.replace(item.value, name)
  }
  return masked ? maskIpsInText(label) : label
}

/** Hosts, hashes and other indicators read better in the monospace face. */
export function isCodeLike(item: TodayItem): boolean {
  return item.kind === "host" || item.kind === "new"
}

/** At most three items per card, whatever the API sends. */
export const MAX_ITEMS = 3

export function visibleItems(items: readonly TodayItem[]): TodayItem[] {
  return items.slice(0, MAX_ITEMS)
}

/**
 * What an item's number counts, so a bare "82" never needs guessing. `null` hides the number:
 * a campaign already says "37 sessions from 9 sources" in its detail line.
 */
const COUNT_UNIT: Record<TodayItem["kind"], [string, string] | null> = {
  sensor: ["session", "sessions"],
  country: ["session", "sessions"],
  tag: ["session", "sessions"],
  service: ["session", "sessions"],
  campaign: null,
  host: ["sighting", "sightings"],
  new: ["time", "times"],
  session: null,
}

export function countUnit(item: TodayItem): string | null {
  const unit = COUNT_UNIT[item.kind]
  if (!unit || item.count == null) return null
  return item.count === 1 ? unit[0] : unit[1]
}

/** "asn:64530" → "asn": which kind of first-seen thing a "new" item is. */
export function newField(item: TodayItem): string | null {
  if (item.kind !== "new") return null
  const i = item.value.indexOf(":")
  return i > 0 ? item.value.slice(0, i) : null
}
