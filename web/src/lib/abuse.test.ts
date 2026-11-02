import { describe, expect, it } from "vitest"
import {
  blockedReason,
  describeAbuseError,
  describeGuard,
  describeReports,
  guardReason,
  guardReasonsOf,
  nextActions,
  reviewBlocker,
  type AbuseStatus,
  type ReportDetail,
} from "./abuse"
import { ApiError } from "./api"

const status = (over: Partial<AbuseStatus> = {}): AbuseStatus => ({
  enabled: true,
  gate: "open",
  rdap_quota: { used: 0, limit: 1000 },
  self_address_known: true,
  self_address_fresh: true,
  counts: { draft: 4, reviewed: 0, sent: 0, closed: 0, discarded: 0, superseded: 0 },
  waiting_for_contact: 0,
  ...over,
})

describe("describeReports", () => {
  it("says how many reports are ready", () => {
    expect(describeReports(status())).toBe("4 drafts to review.")
  })
  it("counts the same things as the tabs", () => {
    expect(describeReports(status(), { toSend: 3, replies: 2 })).toBe(
      "4 drafts to review, 3 reports ready to send, 2 replies to check.",
    )
  })
  it("says when there is nothing to report", () => {
    const s = status({ counts: { ...status().counts, draft: 0 } })
    expect(describeReports(s)).toBe(
      "Nothing to report: no source crossed the thresholds this week.",
    )
  })
})

describe("blockedReason", () => {
  it("explains a missing self address first", () => {
    expect(blockedReason(status({ self_address_known: false }))).toMatch(/not known yet/)
  })
  it("warns when the learned address is stale", () => {
    expect(blockedReason(status({ self_address_fresh: false }))).toMatch(/fresh one/)
  })
  it("points to the settings when the reply contact is missing", () => {
    expect(describeAbuseError(new ApiError(409, "x", "settings_incomplete"))).toBe(
      "Set the reply contact in the Reporting settings first",
    )
  })
  it("is null when everything works", () => {
    expect(blockedReason(status())).toBeNull()
  })
})

describe("identity check wording", () => {
  it("counts what was masked and removed", () => {
    expect(describeGuard({ ok: true, codes: [] }, { masked: 2, removed: 1 })).toBe(
      "Nothing identifying found. 2 addresses masked, 1 line removed.",
    )
  })
  it("explains reason codes in plain English and never shows a value", () => {
    expect(guardReason("project_term")).toMatch(/name of this project/)
    expect(guardReason("something_new")).toMatch(/refused/)
  })
  it("reads the reasons of a blocked answer", () => {
    const e = new ApiError(409, "x", "identity_guard_failed", { reasons: ["self_name"] })
    expect(guardReasonsOf(e)).toEqual(["self_name"])
    expect(guardReasonsOf(new Error("x"))).toBeNull()
  })
})

describe("review rules", () => {
  const base = {
    guard: { ok: true, codes: [] },
    recipient: { mailbox: "abuse@example.net" },
    missing: [],
  } as unknown as ReportDetail
  it("needs a reply contact, and no wording", () => {
    expect(reviewBlocker({ ...base, missing: ["reply_contact"] })).toMatch(/reply contact/)
    expect(reviewBlocker(base)).toBeNull()
  })
  it("is blocked by a failed identity check", () => {
    expect(reviewBlocker({ ...base, guard: { ok: false, codes: ["self_name"] } })).toMatch(
      /blocked/,
    )
  })
  it("follows the workflow", () => {
    expect(nextActions("draft")).toEqual(["reviewed", "discarded"])
    expect(nextActions("sent")).toEqual(["closed"])
    expect(nextActions("closed")).toEqual([])
  })
  it("explains a revision conflict", () => {
    expect(describeAbuseError(new ApiError(409, "x", "revision_mismatch"))).toMatch(/changed/)
  })
})
