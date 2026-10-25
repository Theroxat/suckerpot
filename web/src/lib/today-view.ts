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
