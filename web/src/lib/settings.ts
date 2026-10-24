/**
 * Settings page data (`/api/v1/settings/system` and `/settings/enrichment`) and the
 * plain-English findings each card opens with. Pure functions, unit-tested.
 */
import { formatBytes, formatNumber, formatPercent, formatRelative, plural } from "./format"
import { sensorMeta } from "./sensors"

export type SensorState = "active" | "quiet" | "silent"

export interface SensorStatus {
  sensor: string
  last_event_at: string | null
  events_last_hour: number
  status: SensorState
}

export interface DiskGuard {
  state: "ok" | "trimmed" | "critical"
  active: boolean
  size_bytes: number
  max_bytes: number
  percent: number
  last_trim_at?: string | null
  last_trim_chunks?: number | null
}

export interface IngestDisk {
  degraded: boolean
  degraded_writes: number
  size_bytes: number
  max_bytes: number
  percent: number
}

export interface SystemSettings {
  sensors: SensorStatus[]
  retention: {
    raw_days: number | null
    compression_after_days: number | null
    aggregates: string[]
  }
  disk_guard: DiskGuard | null
  ingest_disk: IngestDisk | null
  database: { size_bytes: number | null; max_bytes: number | null }
}

export interface GeoFile {
  file: string
  bytes: number
  updated_at: string
  age_days?: number | null
}

export interface ReputationProvider {
  configured: boolean
  daily_quota: number | null
  used_today: number
  disabled: string | null
  paused: boolean
  last_error: string | null
}

export interface EnrichmentSettings {
  geoip: {
    /** maxmind | dbip | off | unknown (ingest has not reported yet). */
    provider: string
    available: boolean
    files: Record<string, GeoFile>
    last_error: string | null
    refresh_days: number | null
    attribution: string | null
  }
  abuseipdb: ReputationProvider
  greynoise: ReputationProvider
  reported_at: string | null
}

const label = (s: string) => sensorMeta(s)?.label ?? s.toUpperCase()

function joinAnd(parts: string[]): string {
  if (parts.length <= 1) return parts.join("")
  return `${parts.slice(0, -1).join(", ")} and ${parts.at(-1) ?? ""}`
}

export function sensorsFinding(sensors: readonly SensorStatus[], now = Date.now()): string {
  const active = sensors.filter((s) => s.status === "active")
  const silent = sensors.filter((s) => s.status === "silent")
  const quiet = sensors.filter((s) => s.status === "quiet")
  if (sensors.length > 0 && active.length === sensors.length) {
    return sensors.length === 4
      ? "All four sensors reported in the last 15 minutes."
      : `All ${sensors.length} sensors reported in the last 15 minutes.`
  }
  if (silent.length === sensors.length) return "No sensor has reported in the last 24 hours."
  const parts: string[] = []
  if (active.length)
    parts.push(`${joinAnd(active.map((x) => label(x.sensor)))} reported in the last 15 minutes`)
  for (const q of quiet) {
    parts.push(
      `${label(q.sensor)} last reported ${q.last_event_at ? formatRelative(q.last_event_at, now) : "earlier today"}`,
    )
  }
  if (silent.length) {
    parts.push(
      `${joinAnd(silent.map((x) => label(x.sensor)))} ${silent.length === 1 ? "has" : "have"} not reported in over 24 hours`,
    )
  }
  const head = parts.join("; ")
  return `${head.charAt(0).toUpperCase()}${head.slice(1)}.`
}

function geoProviderName(p: string): string {
  if (p === "maxmind") return "MaxMind GeoLite2"
  if (p === "dbip") return "DB-IP Lite"
  return p
}

/** Oldest GeoIP file age in days, or null. */
export function geoAgeDays(e: EnrichmentSettings): number | null {
  const ages = Object.values(e.geoip.files)
    .map((f) => f.age_days ?? (Date.now() - Date.parse(f.updated_at)) / 86_400_000)
    .filter((n) => Number.isFinite(n))
  return ages.length ? Math.max(...ages) : null
}

export function enrichmentFinding(e: EnrichmentSettings): string {
  const g = e.geoip
  if (g.provider === "unknown") return "Ingest has not reported its enrichment status yet."
  let geo: string
  if (g.provider === "off" || !g.available) geo = "GeoIP is off, so new sessions are not located"
  else {
    const age = geoAgeDays(e)
    geo = `GeoIP is on (${geoProviderName(g.provider)}${age !== null ? `, ${plural(Math.round(age), "day")} old` : ""})`
  }
  const abuse = e.abuseipdb
  if (abuse.configured && abuse.daily_quota) {
    return `${geo}; AbuseIPDB used ${formatNumber(abuse.used_today)} of ${formatNumber(abuse.daily_quota)} checks today.`
  }
  return `${geo}; no reputation provider is configured.`
}

export function retentionFinding(r: SystemSettings["retention"]): string {
  const raw = r.raw_days
    ? `Raw events are kept for ${plural(r.raw_days, "day")}`
    : "Raw events are kept until the disk guard trims them"
  return `${raw}; aggregates are kept forever.`
}

export function storageFinding(s: SystemSettings): string {
  const g = s.disk_guard
  if (g?.state === "critical") {
    return `The database is at ${formatPercent(g.percent / 100)} of its ceiling: new data may be dropped.`
  }
  const size = s.database.size_bytes
  const max = s.database.max_bytes ?? g?.max_bytes ?? null
  if (size === null) return "The database size is not available."
  if (!max) return `The database uses ${formatBytes(size)}.`
  return `The database uses ${formatBytes(size)} of its ${formatBytes(max)} ceiling (${formatPercent(size / max)}).`
}

/** Tone for a used/budget ratio: neutral, then warning from 80 %. Severe is decided by the caller. */
export function usageTone(ratio: number): "neutral" | "warning" {
  return ratio >= 0.8 ? "warning" : "neutral"
}
