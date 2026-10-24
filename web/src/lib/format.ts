/**
 * Formatting helpers. Numbers use en-US grouping (the UI is in English);
 * times are shown in the browser's time zone.
 */

const integer = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 })
const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 })
const percent = new Intl.NumberFormat("en-US", { style: "percent", maximumFractionDigits: 0 })

export function formatNumber(n: number): string {
  return integer.format(n)
}

export function formatCompact(n: number): string {
  return n < 10_000 ? integer.format(n) : compact.format(n)
}

export function formatPercent(ratio: number): string {
  return percent.format(ratio)
}

/** "3 passwords" / "1 password". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${formatNumber(n)} ${n === 1 ? one : many}`
}

const absolute = new Intl.DateTimeFormat("en-US", {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
  timeZoneName: "short",
})

const clock = new Intl.DateTimeFormat("en-US", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
})

export function formatAbsolute(iso: string | Date): string {
  return absolute.format(typeof iso === "string" ? new Date(iso) : iso)
}

export function formatClock(iso: string | Date): string {
  return clock.format(typeof iso === "string" ? new Date(iso) : iso)
}

export function browserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone
}

const rtf = new Intl.RelativeTimeFormat("en-US", { numeric: "auto", style: "short" })

/** "just now", "42 sec. ago", "5 min. ago", "3 hr. ago", "yesterday", then a date. */
export function formatRelative(iso: string | Date, now: number = Date.now()): string {
  const t = (typeof iso === "string" ? new Date(iso) : iso).getTime()
  const diff = Math.round((t - now) / 1000)
  const abs = Math.abs(diff)
  if (abs < 10) return "just now"
  if (abs < 60) return rtf.format(diff, "second")
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute")
  if (abs < 86_400) return rtf.format(Math.round(diff / 3600), "hour")
  if (abs < 7 * 86_400) return rtf.format(Math.round(diff / 86_400), "day")
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(t)
}

/** "8 s", "1 min 40 s", "2 h 05 min". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s} s`
  if (s < 3600) {
    const m = Math.floor(s / 60)
    const r = s % 60
    return r ? `${m} min ${r} s` : `${m} min`
  }
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return `${h} h ${String(m).padStart(2, "0")} min`
}

const regionNames = new Intl.DisplayNames(["en"], { type: "region" })

/** ISO 3166-1 alpha-2 code -> English name. Unknown codes return null. */
export function countryName(code: string | null | undefined): string | null {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return null
  try {
    const name = regionNames.of(code.toUpperCase())
    return name && name !== code.toUpperCase() && name !== "Unknown Region" ? name : null
  } catch {
    return null
  }
}

/** Mask an address for sharing: 203.0.113.42 -> 203.0.x.x, 2001:db8:1::5 -> 2001:db8:x::x. */
export function maskIp(ip: string): string {
  if (ip.includes(":")) {
    const parts = ip.split(":").filter(Boolean)
    return `${parts.slice(0, 2).join(":")}:x::x`
  }
  const parts = ip.split(".")
  return parts.length === 4 ? `${parts.slice(0, 2).join(".")}.x.x` : ip
}

const IPV4_IN_TEXT = /\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b/g

/** Mask every IPv4 address inside free text (URLs, commands, summaries). */
export function maskIpsInText(text: string): string {
  return text.replace(IPV4_IN_TEXT, "$1.x.x")
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const

/** Decimal units, one decimal above KB: "3.2 GB", "512 MB", "820 B". */
export function formatBytes(bytes: number): string {
  let v = Math.max(0, bytes)
  let i = 0
  while (v >= 1000 && i < BYTE_UNITS.length - 1) {
    v /= 1000
    i++
  }
  const unit = BYTE_UNITS[i] ?? "B"
  return i === 0
    ? `${Math.round(v)} ${unit}`
    : `${v >= 100 ? Math.round(v) : v.toFixed(1).replace(/\.0$/, "")} ${unit}`
}
