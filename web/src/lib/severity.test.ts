import { describe, expect, it } from "vitest"
import { isSevereEvent, tagSeverity } from "./severity"

describe("tag severity", () => {
  it("marks payload and exploit tags severe, harmful ones warning, the rest neutral", () => {
    for (const t of ["container-escape", "sql-rce", "eternalblue", "php2shell", "mirai"])
      expect(tagSeverity(t)).toBe("severe")
    for (const t of ["db-ransom", "redis-rogue-master", "sip-fraud", "persistence"])
      expect(tagSeverity(t)).toBe("warning")
    expect(tagSeverity("recon")).toBeNull()
  })
  it("reds only the event that carries the exploit", () => {
    expect(isSevereEvent("download_attempt", [])).toBe(true)
    expect(isSevereEvent("http_request", ["php2shell"])).toBe(true)
    expect(isSevereEvent("http_request", ["container-escape"])).toBe(true)
    expect(isSevereEvent("scan", ["eternalblue"])).toBe(true)
    expect(isSevereEvent("command", ["sql-rce"])).toBe(true)
    expect(isSevereEvent("login_attempt", ["sql-rce"])).toBe(false)
    expect(isSevereEvent("command", ["db-ransom"])).toBe(false)
  })
})
