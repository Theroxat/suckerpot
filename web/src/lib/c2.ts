/** Probable command-and-control addresses (read-only): types, wording and the page sentence. */
import { plural } from "./format"
import { safeReference } from "./infrastructure"

export type C2Confidence = "high" | "medium"

export interface C2Hash {
  sha256: string
  family: string | null
}

export interface C2Address {
  /** Raw address. Never rendered: the UI only shows `defanged`. */
  address: string
  defanged: string
  kind: "ip" | "domain"
  port: number | null
  confidence: C2Confidence
  sources: ("virustotal" | "threatfox")[]
  families: string[]
  hashes: C2Hash[]
  hash_count: number
  sessions: number
  first_seen: string
  last_seen: string
  references: string[]
}

export interface C2Page {
  items: C2Address[]
  next_cursor: string | null
}

export const C2_CONFIDENCE_LABELS: Record<C2Confidence, string> = {
  high: "Reported as C2 by ThreatFox",
  medium: "Seen contacted in a VirusTotal sandbox",
}

/** Only the https links to the intel services are ever shown. */
export function c2References(item: Pick<C2Address, "references">): string[] {
  return item.references.map(safeReference).filter((u): u is string => u !== null)
}

export function referenceLabel(url: string): string {
  return url.startsWith("https://www.virustotal.com/") ? "VirusTotal" : "ThreatFox"
}

/** The sentence the section opens with. */
export function describeC2(items: readonly C2Address[], more: boolean): string {
  if (items.length === 0) return "No control server is known for the malware dropped here yet."
  const single = items.length === 1 && !more
  const high = items.filter((i) => i.confidence === "high").length
  const base = `${items.length}${more ? "+" : ""} ${single ? "address is" : "addresses are"} probably the ${single ? "control server" : "control servers"} of malware dropped on your decoys.`
  return high > 0
    ? `${base} ${plural(high, "was", "were")} reported as C2 by ThreatFox. Block them.`
    : `${base} Block them.`
}
