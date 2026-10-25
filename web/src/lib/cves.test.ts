import { describe, expect, it } from "vitest"
import {
  cveTitle,
  describeCves,
  proposedTag,
  serviceLabel,
  sinceParam,
  trapSheet,
  type CveDetail,
  type CveItem,
} from "./cves"

const ITEM: CveItem = {
  cve_id: "CVE-2099-10001",
  title: "Example PHP flaw",
  description: null,
  vendor: "Example",
  product: "PHP",
  published_at: "2099-01-01T00:00:00Z",
  modified_at: null,
  cvss_score: 9.2,
  cvss_severity: "CRITICAL",
  in_kev: true,
  kev_added_at: null,
  kev_due_date: null,
  kev_ransomware: null,
  relevance: "high",
  matched_services: ["web-php", "mystery"],
  tags: ["php2shell"],
  sources: ["kev"],
  seen_sessions: 3,
}

const DETAIL: CveDetail = {
  item: ITEM,
  description_full: "x",
  cwes: [],
  ghsa_ids: [],
  refs: ["https://example.com/a"],
  cpes: [],
  kev_action: null,
  traffic: { sessions: 3, ips: 2, first_seen: null, last_seen: null, by_tag: [] },
}

describe("describeCves", () => {
  it("says so when nothing matters", () => {
    expect(describeCves({ critical: 0, relevant: 0, kevRelevant: 0, seen: 0 })).toBe(
      "No new CVE this week affects the services we emulate.",
    )
  })
  it("leads with critical CVEs and adds KEV and traffic", () => {
    expect(describeCves({ critical: 3, relevant: 5, kevRelevant: 1, seen: 2 })).toBe(
      "3 new critical CVEs this week affect services we emulate: 1 already exploited in the wild (CISA KEV), 2 seen in our traffic.",
    )
  })
  it("uses the singular and falls back to all relevant CVEs", () => {
    expect(describeCves({ critical: 1, relevant: 1, kevRelevant: 0, seen: 0 })).toBe(
      "1 new critical CVE this week affects services we emulate.",
    )
    expect(describeCves({ critical: 0, relevant: 4, kevRelevant: 0, seen: 0 })).toBe(
      "4 new CVEs this week affect services we emulate.",
    )
  })
})

describe("helpers", () => {
  it("builds a stable, rounded since parameter", () => {
    const now = Date.parse("2099-03-10T10:20:30Z")
    expect(sinceParam("7", now)).toBe("2099-03-03T10:00:00.000Z")
    expect(sinceParam("all", now)).toBeUndefined()
    expect(sinceParam("abc", now)).toBeUndefined()
    expect(sinceParam(null, now)).toBeUndefined()
  })
  it("labels services and falls back to the id", () => {
    expect(serviceLabel("redis")).toBe("Redis")
    expect(serviceLabel("mystery")).toBe("mystery")
  })
  it("names a CVE from its title, then vendor and product, then id", () => {
    expect(cveTitle(ITEM)).toBe("Example PHP flaw")
    expect(cveTitle({ ...ITEM, title: null })).toBe("Example PHP")
    expect(cveTitle({ ...ITEM, title: null, vendor: null, product: null })).toBe("CVE-2099-10001")
  })
  it("proposes a safe tag name", () => {
    expect(proposedTag("CVE-2099-10001")).toBe("cve-2099-10001")
  })
})

describe("trapSheet", () => {
  it("is a plain-text template that never promises automation", () => {
    const sheet = trapSheet(DETAIL)
    expect(sheet).toContain("Trap proposal: CVE-2099-10001")
    expect(sheet).toContain("Apache + PHP -> web sensor")
    expect(sheet).toContain("mystery -> to be decided")
    expect(sheet).toContain("Tag name: cve-2099-10001")
    expect(sheet).toContain("3 sessions from 2 addresses")
    expect(sheet).toContain("Nothing is built or deployed from this sheet.")
  })
})
