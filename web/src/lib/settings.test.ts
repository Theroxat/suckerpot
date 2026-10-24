import { formatBytes } from "./format"
import {
  enrichmentFinding,
  retentionFinding,
  sensorsFinding,
  storageFinding,
  type EnrichmentSettings,
  type SensorStatus,
  type SystemSettings,
} from "./settings"

const NOW = Date.parse("2026-10-24T18:00:00Z")
const s = (sensor: string, status: SensorStatus["status"], last: string | null): SensorStatus => ({
  sensor,
  status,
  last_event_at: last,
  events_last_hour: 10,
})

describe("settings findings", () => {
  it("sensors", () => {
    const all = ["ssh", "telnet", "web", "rdp"].map((x) => s(x, "active", "2026-10-24T17:58:00Z"))
    expect(sensorsFinding(all, NOW)).toBe("All four sensors reported in the last 15 minutes.")
    const mixed = [
      s("ssh", "active", "2026-10-24T17:58:00Z"),
      s("telnet", "quiet", "2026-10-24T15:00:00Z"),
      s("web", "active", "2026-10-24T17:59:00Z"),
      s("rdp", "silent", null),
    ]
    expect(sensorsFinding(mixed, NOW)).toBe(
      "SSH and Web reported in the last 15 minutes; Telnet last reported 3 hr. ago; RDP has not reported in over 24 hours.",
    )
    expect(
      sensorsFinding(
        mixed.map((m) => ({ ...m, status: "silent" as const })),
        NOW,
      ),
    ).toBe("No sensor has reported in the last 24 hours.")
  })

  const enrich: EnrichmentSettings = {
    geoip: {
      provider: "dbip",
      available: true,
      files: {
        city: { file: "c.mmdb", bytes: 1, updated_at: "2026-10-01T00:00:00Z", age_days: 23.6 },
      },
      last_error: null,
      refresh_days: 30,
      attribution: "IP geolocation by DB-IP.com",
    },
    abuseipdb: {
      configured: true,
      daily_quota: 1000,
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
    reported_at: null,
  }

  it("enrichment", () => {
    expect(enrichmentFinding(enrich)).toBe(
      "GeoIP is on (DB-IP Lite, 24 days old); AbuseIPDB used 312 of 1,000 checks today.",
    )
    expect(
      enrichmentFinding({
        ...enrich,
        geoip: { ...enrich.geoip, provider: "off", available: false },
      }),
    ).toMatch(/^GeoIP is off/)
    expect(enrichmentFinding({ ...enrich, geoip: { ...enrich.geoip, provider: "unknown" } })).toBe(
      "Ingest has not reported its enrichment status yet.",
    )
  })

  const GUARD = {
    state: "ok",
    active: true,
    size_bytes: 3.2e9,
    max_bytes: 20e9,
    percent: 16,
  } as const
  const sys: SystemSettings = {
    sensors: [],
    retention: { raw_days: 90, compression_after_days: 7, aggregates: ["events_hourly"] },
    disk_guard: GUARD,
    ingest_disk: null,
    database: { size_bytes: 3.2e9, max_bytes: 20e9 },
  }

  it("retention and storage", () => {
    expect(retentionFinding(sys.retention)).toBe(
      "Raw events are kept for 90 days; aggregates are kept forever.",
    )
    expect(storageFinding(sys)).toBe("The database uses 3.2 GB of its 20 GB ceiling (16%).")
    expect(
      storageFinding({ ...sys, disk_guard: { ...GUARD, state: "critical", percent: 97 } }),
    ).toMatch(/97%/)
    expect(storageFinding({ ...sys, database: { size_bytes: null, max_bytes: null } })).toBe(
      "The database size is not available.",
    )
  })

  it("formats bytes", () => {
    expect(formatBytes(820)).toBe("820 B")
    expect(formatBytes(3_200_000_000)).toBe("3.2 GB")
    expect(formatBytes(512_000_000)).toBe("512 MB")
  })
})
