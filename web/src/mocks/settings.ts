import { delay, http, HttpResponse } from "msw"
import type { EnrichmentSettings, SystemSettings } from "@/lib/settings"

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString()
const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000).toISOString()

/** `GET /api/v1/settings/system`: three busy sensors, RDP quiet for a couple of hours. */
export function systemSettings(): SystemSettings {
  return {
    sensors: [
      { sensor: "ssh", last_event_at: minutesAgo(0.2), events_last_hour: 2_418, status: "active" },
      { sensor: "telnet", last_event_at: minutesAgo(1), events_last_hour: 1_096, status: "active" },
      { sensor: "web", last_event_at: minutesAgo(3), events_last_hour: 1_731, status: "active" },
      { sensor: "rdp", last_event_at: minutesAgo(134), events_last_hour: 0, status: "quiet" },
    ],
    retention: {
      raw_days: 90,
      compression_after_days: 7,
      aggregates: ["events_hourly", "events_daily_tags", "events_daily_country", "events_daily_ip"],
    },
    disk_guard: {
      state: "ok",
      active: true,
      size_bytes: 3_412_000_000,
      max_bytes: 20_000_000_000,
      percent: 17.1,
      last_trim_at: null,
      last_trim_chunks: null,
    },
    ingest_disk: {
      degraded: false,
      degraded_writes: 0,
      size_bytes: 41_000_000,
      max_bytes: 1_000_000_000,
      percent: 4.1,
    },
    database: { size_bytes: 3_412_000_000, max_bytes: 20_000_000_000 },
  }
}

/** `GET /api/v1/settings/enrichment`: DB-IP Lite, AbuseIPDB on, GreyNoise off. */
export function enrichmentSettings(): EnrichmentSettings {
  return {
    geoip: {
      provider: "dbip",
      available: true,
      files: {
        city: {
          file: "dbip-city-lite.mmdb",
          bytes: 131_072_000,
          updated_at: daysAgo(23.6),
          age_days: 23.6,
        },
        asn: {
          file: "dbip-asn-lite.mmdb",
          bytes: 9_437_184,
          updated_at: daysAgo(23.6),
          age_days: 23.6,
        },
      },
      last_error: null,
      refresh_days: 30,
      attribution: "IP geolocation by DB-IP.com (https://db-ip.com), CC BY 4.0",
    },
    abuseipdb: {
      configured: true,
      daily_quota: 1_000,
      used_today: 312,
      disabled: null,
      paused: false,
      last_error: null,
    },
    greynoise: {
      configured: false,
      daily_quota: null,
      used_today: 0,
      disabled: null,
      paused: false,
      last_error: null,
    },
    reported_at: minutesAgo(2),
  }
}

export const settingsHandlers = [
  http.get("/api/v1/settings/system", async () => {
    await delay(150)
    return HttpResponse.json(systemSettings())
  }),
  http.get("/api/v1/settings/enrichment", async () => {
    await delay(150)
    return HttpResponse.json(enrichmentSettings())
  }),
]
