import { afterEach, describe, expect, it, vi } from "vitest"
import { ApiError } from "./api"
import {
  blocklistSentence,
  classifyFailure,
  createFeedToken,
  describeDefendError,
  detectionsExportUrl,
  detectionsSentence,
  exportUrl,
  exposureSentence,
  feedCurl,
  feedsSentence,
  feedUrl,
  firewallInstructions,
  kindsPhrase,
  parseMinScore,
  SCORE_OPTIONS,
  parseDays,
  previousComparison,
  reasonLabel,
  REASON_LABELS,
  scoreBand,
  validateInventory,
  type DefendSummary,
  type ExposureReport,
  type ExposureService,
} from "./defend"

function summary(listed: Partial<Record<"ip" | "domain" | "url" | "hash", number>>): DefendSummary {
  return {
    computed_at: null,
    worker_enabled: true,
    feeds_enabled: true,
    kinds: (["ip", "domain", "url", "hash"] as const).map((kind) => ({
      kind,
      total: 100,
      high: 0,
      listed: listed[kind] ?? 0,
    })),
    top_reasons: [],
    demo_entries: 0,
    overrides: 0,
  }
}

describe("blocklistSentence", () => {
  it("lists every kind that has entries, with thousands separators", () => {
    expect(blocklistSentence(summary({ ip: 1204, domain: 3, url: 2 }))).toBe(
      "1,204 addresses, 3 domains and 2 URLs scored 50 or higher and are ready for your firewall.",
    )
  })
  it("uses singular grammar for one entry", () => {
    expect(blocklistSentence(summary({ ip: 1 }))).toBe(
      "1 address scored 50 or higher and is ready for your firewall.",
    )
  })
  it("says so when nothing is listed", () => {
    expect(blocklistSentence(summary({}))).toMatch(/Nothing has scored 50 or higher/)
  })
  it("has a neutral sentence while loading", () => {
    expect(blocklistSentence(undefined)).toMatch(/ready for your firewall/)
  })
})

describe("reasons and scores", () => {
  it("maps every documented reason code to a plain label", () => {
    const codes = [
      "brute-force",
      "login-succeeded",
      "ran-commands",
      "dropped-malware",
      "exploit-attempt",
      "reported-abusive",
      "multi-sensor",
      "campaign",
      "repeat-visitor",
      "mass-scanner",
      "download-source",
      "contacted-by-attacker",
      "known-malware",
      "malware-family",
      "seen-from-many-sources",
      "file-hash",
      "manual-block",
    ]
    for (const c of codes) expect(REASON_LABELS[c]?.label, c).toBeTruthy()
  })
  it("falls back to the code without dashes", () => {
    expect(reasonLabel("some-new-reason")).toBe("some new reason")
  })
  it("bands a score", () => {
    expect(scoreBand(70)).toBe("high")
    expect(scoreBand(50)).toBe("listed")
    expect(scoreBand(49)).toBe("seen")
  })
})

describe("urls", () => {
  it("builds the export link", () => {
    expect(exportUrl({ kind: "ip", format: "alias", minScore: 70 })).toBe(
      "/api/v1/defend/export?kind=ip&format=alias&min_score=70",
    )
  })
  it("falls back to a plain list where the alias format does not apply", () => {
    expect(exportUrl({ kind: "domain", format: "alias", minScore: 50 })).toContain("format=txt")
  })
  it("builds the detection export link", () => {
    expect(detectionsExportUrl("suricata", 90)).toBe(
      "/api/v1/defend/detections/export?kind=suricata&days=90",
    )
  })
  it("builds the feed forms", () => {
    expect(feedUrl("https://dash.example.org/", "T0K", "ip")).toBe(
      "https://dash.example.org/feeds/T0K/ip.txt",
    )
    expect(feedCurl("https://dash.example.org", "T0K")).toBe(
      'curl -H "Authorization: Bearer T0K" https://dash.example.org/feeds/ip.txt',
    )
  })
  it("explains the URL table alias for both firewalls", () => {
    for (const fw of ["opnsense", "pfsense"] as const) {
      const text = firewallInstructions(fw, "https://x/feeds/t/ip.txt").join("\n")
      expect(text).toMatch(/URL Table \(IPs\)/)
      expect(text).toContain("https://x/feeds/t/ip.txt")
    }
  })
})

describe("detections and exposure sentences", () => {
  it("counts the rules and the period", () => {
    expect(detectionsSentence(12, 30)).toBe(
      "We wrote 12 detection rules from attacks seen in the last 30 days. Review each one before you deploy it.",
    )
    expect(detectionsSentence(1, 1)).toMatch(
      /1 detection rule from attacks seen in the last 1 day\./,
    )
    expect(detectionsSentence(0, 7)).toMatch(/No detection rules yet/)
  })

  function service(exposure: "internet" | "vpn", sessions: number): ExposureService {
    return {
      item: {
        id: 1,
        name: "x",
        service: "ssh",
        product: null,
        version: null,
        exposure,
        notes: null,
        created_by: "a",
        created_at: "",
        updated_at: "",
      },
      label: "SSH",
      verdict: "internet_targeted",
      attacks: {
        sessions,
        sources: 3,
        deep_sessions: 0,
        previous_sessions: 0,
        last_attack_at: null,
      },
      top_tags: [],
      cves: [],
      checks: [],
    }
  }
  const report = (services: ExposureService[]): ExposureReport => ({
    days: 30,
    generated_at: "",
    services,
    unlisted: [],
  })

  it("counts the services that face the internet", () => {
    const r = report([service("internet", 1000), service("internet", 204), service("vpn", 50)])
    expect(exposureSentence(r, 30)).toBe(
      "You told us you run 3 services; 2 of them face the internet and were targeted 1,204 times in the last 30 days.",
    )
  })
  it("uses singular verbs for one", () => {
    expect(exposureSentence(report([service("internet", 1)]), 7)).toBe(
      "You told us you run 1 service; 1 of them faces the internet and was targeted 1 time in the last 7 days.",
    )
  })
  it("invites the person to add a service when the list is empty", () => {
    expect(exposureSentence(report([]), 30)).toMatch(/Tell us what you run/)
  })
  it("compares with the period before in neutral words", () => {
    expect(previousComparison(120, 100)).toBe("up 20% from 100 before")
    expect(previousComparison(50, 100)).toBe("down 50% from 100 before")
    expect(previousComparison(102, 100)).toMatch(/about the same/)
    expect(previousComparison(5, 0)).toBe("none in the period before")
  })
})

describe("score presets", () => {
  it("offers the same three choices everywhere, Balanced by default", () => {
    expect(SCORE_OPTIONS.map((o) => o.label)).toEqual([
      "High confidence 70+",
      "Balanced 50+",
      "Everything 20+",
    ])
    expect(parseMinScore(null)).toBe(50)
    expect(parseMinScore("70")).toBe(70)
    expect(parseMinScore("20")).toBe(20)
    expect(parseMinScore("10")).toBe(50)
    expect(parseMinScore("junk")).toBe(50)
  })
})

describe("feeds", () => {
  it("explains the off state and the empty state", () => {
    expect(feedsSentence({ enabled: false, items: [] })).toMatch(/Feeds are off/)
    expect(feedsSentence({ enabled: true, items: [] })).toMatch(/no token exists yet/)
  })
  it("names the kinds a token covers", () => {
    expect(kindsPhrase(["domain", "ip"])).toBe("IP addresses and domains")
    expect(kindsPhrase(["url", "hash", "domain"])).toBe("domains, URLs and file hashes")
  })
})

describe("inventory and periods", () => {
  it("requires a name", () => {
    expect(validateInventory({ name: "  ", service: "ssh", exposure: "internet" }).name).toMatch(
      /name/,
    )
    expect(validateInventory({ name: "Jump host", service: "ssh", exposure: "vpn" })).toEqual({})
  })
  it("only accepts the offered periods", () => {
    expect(parseDays("90")).toBe(90)
    expect(parseDays("45")).toBe(30)
    expect(parseDays(null)).toBe(30)
  })
})

describe("errors", () => {
  it("classifies the documented codes", () => {
    expect(classifyFailure(new ApiError(403, "x", "reauth_failed"))).toBe("wrong-password")
    expect(classifyFailure(new ApiError(429, "x"))).toBe("rate-limited")
    expect(classifyFailure(new ApiError(401, "x", "session_revoked"))).toBe("session")
    expect(classifyFailure(new ApiError(409, "x", "feeds_disabled"))).toBe("feeds-disabled")
    expect(classifyFailure(new ApiError(409, "x", "limit_reached"))).toBe("limit")
    expect(classifyFailure(new Error("offline"))).toBe("network")
  })
  it("shows the API's own sentence for a refused value", () => {
    expect(
      describeDefendError(new ApiError(422, "That address is private.", "invalid_value")),
    ).toBe("That address is private.")
  })
  it("mentions the env var when feeds are disabled", () => {
    expect(describeDefendError(new ApiError(409, "x", "feeds_disabled"))).toMatch(/FEEDS_ENABLED/)
  })
})

describe("createFeedToken", () => {
  afterEach(() => vi.unstubAllGlobals())

  it("sends the password and the options, and resolves to the one-time token", async () => {
    const calls: { url: string; body: unknown }[] = []
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string, init?: RequestInit) => {
        if (url.endsWith("/auth/csrf"))
          return Promise.resolve(new Response(JSON.stringify({ token: "t" }), { status: 200 }))
        calls.push({
          url,
          body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
        })
        return Promise.resolve(
          new Response(JSON.stringify({ token: "secret", item: { id: 1 } }), { status: 201 }),
        )
      }),
    )
    const out = await createFeedToken(
      { name: " Edge ", kinds: ["ip"], minScore: 60, includeBenign: false, expiresInDays: 30 },
      "pw",
    )
    expect(out.token).toBe("secret")
    expect(calls[0]).toEqual({
      url: "/api/v1/defend/feed-tokens",
      body: {
        name: "Edge",
        kinds: ["ip"],
        min_score: 60,
        include_benign: false,
        expires_in_days: 30,
        password: "pw",
      },
    })
  })
})
