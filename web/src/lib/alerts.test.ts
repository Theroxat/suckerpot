import { describe, expect, it } from "vitest"
import { ApiError } from "@/lib/api"
import {
  AlertError,
  channelsFinding,
  describeError,
  describeTest,
  outboxFinding,
  reportsFinding,
  rulesFinding,
  testInFlight,
  toAlertError,
  weekLabel,
  type AlertChannel,
  type AlertRule,
  type AlertStatus,
  type OutboxItem,
  type ReportItem,
} from "./alerts"

const status = (enabled: boolean): AlertStatus => ({
  alerts: {
    enabled,
    smtp_configured: false,
    can_decrypt: true,
    last_error: null,
    updated_at: null,
  },
  reports_enabled: true,
  editing_enabled: true,
  editing_reason: null,
  channels: 0,
  limits: { per_minute: 10, per_day: 100, all_channels_per_day: 300 },
})

function channel(over: Partial<AlertChannel> = {}): AlertChannel {
  return {
    id: 1,
    kind: "discord",
    name: "SecOps",
    enabled: true,
    target_hint: "discord.com",
    mask_ips: true,
    created_by: "admin",
    created_at: "2026-10-20T08:00:00Z",
    updated_at: "2026-10-20T08:00:00Z",
    last_test: null,
    ...over,
  }
}

describe("findings", () => {
  it("says nothing is sent when the server has alerts off", () => {
    expect(channelsFinding(status(false), [channel()])).toMatch(/switched off on this server/)
  })
  it("asks for a first channel", () => {
    expect(channelsFinding(status(true), [])).toBe("No channel yet. Add one to receive alerts.")
  })
  it("counts ready channels and failed tests", () => {
    const ok = channel()
    const bad = channel({
      id: 2,
      last_test: { state: "failed", detail: "http_404", requested_at: "2026-10-25T10:00:00Z" },
    })
    expect(channelsFinding(status(true), [ok])).toBe("1 channel is ready to receive alerts.")
    expect(channelsFinding(status(true), [ok, bad])).toBe(
      "2 channels are ready to receive alerts. 1 test failed, check the details below.",
    )
  })
  it("describes the rules", () => {
    const rule = (enabled: boolean): AlertRule => ({
      kind: "malware_drop",
      enabled,
      channel_ids: [1],
      min_severity: "severe",
    })
    expect(rulesFinding([rule(false)], [])).toMatch(/add a channel/)
    expect(rulesFinding([rule(false)], [channel()])).toMatch(/Every alert is off/)
    expect(rulesFinding([rule(true), rule(true)], [channel()])).toBe(
      "2 alerts are on. Everything else stays quiet.",
    )
  })
  it("describes the outbox and the reports", () => {
    const item = (state: OutboxItem["state"]): OutboxItem => ({
      id: 1,
      rule_kind: "malware_drop",
      channel_id: 1,
      channel_name: "SecOps",
      state,
      attempts: 1,
      created_at: "2026-10-25T10:00:00Z",
      sent_at: null,
      error_code: null,
      severity: "severe",
      title: "t",
      summary: null,
    })
    expect(outboxFinding([])).toBe("No alert has been queued yet.")
    expect(outboxFinding([item("sent"), item("failed")])).toBe(
      "1 alert sent recently, 1 could not be delivered.",
    )
    expect(reportsFinding([])).toMatch(/No weekly report yet/)
    const report = { week_start: "2026-10-12", headline: "A quiet week." } as ReportItem
    expect(reportsFinding([report])).toBe("A quiet week.")
  })
})

describe("test status", () => {
  it("explains each state in a sentence", () => {
    expect(describeTest(null)).toBeNull()
    const at = "2026-10-25T10:00:00Z"
    expect(describeTest({ state: "queued", detail: null, requested_at: at })).toMatch(/requested/)
    expect(describeTest({ state: "done", detail: "sent", requested_at: at })).toMatch(/arrived/)
    expect(describeTest({ state: "refused", detail: "private_address", requested_at: at })).toMatch(
      /private network/,
    )
    expect(
      testInFlight([channel({ last_test: { state: "queued", detail: null, requested_at: at } })]),
    ).toBe(true)
    expect(testInFlight([channel()])).toBe(false)
  })
  it("never leaks an unknown code", () => {
    expect(describeError("weird_code")).toBe("Something went wrong.")
    expect(describeError(null)).toBe("")
  })
})

describe("weekLabel", () => {
  it("shows Monday to Sunday as written, whatever the time zone", () => {
    expect(weekLabel("2026-10-12")).toBe("Oct 12 to Oct 18")
    expect(weekLabel("2026-12-28", "2027-01-03")).toBe("Dec 28 to Jan 3")
  })
})

describe("errors", () => {
  it("maps API codes to reasons", () => {
    const code = (status: number, c: string) => toAlertError(new ApiError(status, "x", c)).reason
    expect(code(403, "reauth_failed")).toBe("wrong-password")
    expect(code(401, "password_required")).toBe("password-required")
    expect(code(422, "invalid_target")).toBe("invalid-target")
    expect(code(422, "no_channel")).toBe("no-channel")
    expect(code(409, "alerts_disabled")).toBe("alerts-disabled")
    expect(code(429, "cooldown")).toBe("rate-limited")
    expect(toAlertError(new Error("boom")).reason).toBe("network")
    expect(toAlertError(new AlertError("session")).reason).toBe("session")
  })
  it("keeps the server's sentence for a refused address, but nothing else", () => {
    const e = toAlertError(
      new ApiError(422, "This is not a Discord webhook URL.", "invalid_target"),
    )
    expect(e.message).toBe("This is not a Discord webhook URL.")
    expect(toAlertError(new ApiError(500, "SQL error at secret")).message).not.toMatch(/secret/)
  })
})
