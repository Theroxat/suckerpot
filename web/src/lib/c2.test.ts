import { describe, expect, it } from "vitest"
import { c2References, describeC2, type C2Address } from "./c2"

const item = (over: Partial<C2Address> = {}): C2Address => ({
  address: "203.0.113.7",
  defanged: "203[.]0[.]113[.]7",
  kind: "ip",
  port: 4444,
  confidence: "medium",
  sources: ["virustotal"],
  families: [],
  hashes: [],
  hash_count: 0,
  sessions: 1,
  first_seen: "2026-10-20T10:00:00Z",
  last_seen: "2026-10-21T10:00:00Z",
  references: [],
  ...over,
})

describe("describeC2", () => {
  it("explains the empty case", () => {
    expect(describeC2([], false)).toMatch(/No control server/)
  })
  it("tells the owner to block them", () => {
    expect(describeC2([item(), item(), item()], false)).toBe(
      "3 addresses are probably the control servers of malware dropped on your decoys. Block them.",
    )
  })
  it("uses the singular and counts high confidence", () => {
    expect(describeC2([item({ confidence: "high" })], false)).toBe(
      "1 address is probably the control server of malware dropped on your decoys. 1 was reported as C2 by ThreatFox. Block them.",
    )
  })
  it("marks a partial count", () => {
    expect(describeC2([item(), item()], true)).toMatch(/^2\+ addresses/)
  })
})

describe("c2References", () => {
  it("keeps only the https intel links", () => {
    const refs = [
      "https://www.virustotal.com/gui/file/abc",
      "https://threatfox.abuse.ch/ioc/1/",
      "http://www.virustotal.com/x",
      "https://evil.example/x",
      "javascript:alert(1)",
    ]
    expect(c2References(item({ references: refs }))).toEqual(refs.slice(0, 2))
  })
})
