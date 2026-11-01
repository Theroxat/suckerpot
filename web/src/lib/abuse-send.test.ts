import { describe, expect, it } from "vitest"
import { ApiError } from "./api"
import {
  buildMailto,
  describeQueue,
  describeRequest,
  describeSendError,
  describeSendErrorCode,
  MAILTO_LIMIT,
  queueRefetch,
  SEND_ERROR,
  type QueueItem,
} from "./abuse-send"

describe("buildMailto", () => {
  it("carries recipient, subject and a short body", () => {
    const m = buildMailto("abuse@example.net", "Abuse report & more", "Hello\nWorld")
    expect(m.bodyIncluded).toBe(true)
    expect(m.href.startsWith("mailto:abuse@example.net?subject=Abuse%20report%20%26%20more")).toBe(
      true,
    )
    expect(m.href).toContain("&body=Hello%0D%0AWorld")
  })
  it("drops the body when the whole link would reach the limit", () => {
    const m = buildMailto("abuse@example.net", "Subject", "x".repeat(3000))
    expect(m.bodyIncluded).toBe(false)
    expect(m.href).not.toContain("body=")
    expect(m.href.length).toBeLessThan(MAILTO_LIMIT)
  })
})

describe("sentences", () => {
  it("maps every worker error code to a sentence", () => {
    for (const code of Object.keys(SEND_ERROR)) {
      expect(describeSendErrorCode(code).length).toBeGreaterThan(20)
    }
    expect(describeSendErrorCode("weird")).toBe("The message could not be sent.")
    expect(describeSendErrorCode(null)).toBe("The message could not be sent.")
  })
  it("describes a request", () => {
    expect(describeRequest(null)).toBeNull()
    expect(describeRequest({ status: "pending", error_code: null, done_at: null })).toBe("Sending…")
    expect(describeRequest({ status: "failed", error_code: "auth_failed", done_at: null })).toMatch(
      /^Not sent\. The mail server refused the username/,
    )
    expect(describeRequest({ status: "cancelled", error_code: null, done_at: null })).toMatch(
      /Cancelled/,
    )
  })
  it("maps 409 codes, 422 problems and reauth", () => {
    expect(describeSendError(new ApiError(409, "x", "smtp_off"))).toMatch(/switched off/)
    expect(describeSendError(new ApiError(409, "x", "not_ready"))).toMatch(/not ready/)
    expect(describeSendError(new ApiError(409, "x", "already_pending"))).toMatch(/already/)
    expect(describeSendError(new ApiError(409, "x", "cap_reached"))).toMatch(/daily limit/)
    expect(describeSendError(new ApiError(403, "x", "reauth_failed"))).toBe(
      "That password is not right.",
    )
    expect(
      describeSendError(
        new ApiError(422, "x", "invalid", { problems: ["bad_host", "owner_domain"] }),
      ),
    ).toMatch(/not an address.*belongs to you/)
    expect(describeSendError(new Error("boom"))).toMatch(/did not work/)
  })
  it("counts the queue", () => {
    expect(describeQueue(0)).toBe("Nothing is waiting to be sent.")
    expect(describeQueue(1)).toBe("1 report is ready to send.")
    expect(describeQueue(12)).toBe("12 reports are ready to send.")
  })
})

describe("queueRefetch", () => {
  const item = (over: Partial<QueueItem>): QueueItem => ({
    id: "a",
    recipient: "abuse@example.net",
    subject: "s",
    body_text: "b",
    scheduled_at: null,
    last_request: null,
    ...over,
  })
  it("polls only while something is on its way", () => {
    expect(queueRefetch(undefined)).toBe(false)
    expect(queueRefetch([item({})])).toBe(false)
    expect(queueRefetch([item({ scheduled_at: "2026-11-01T10:00:00Z" })])).toBe(4000)
    expect(
      queueRefetch([
        item({ last_request: { status: "pending", error_code: null, done_at: null } }),
      ]),
    ).toBe(4000)
  })
})
