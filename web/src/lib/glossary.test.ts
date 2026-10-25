import { describe, expect, it } from "vitest"
import { GLOSSARY, TERM_IDS, isTermId, lookupTerm, splitTerms } from "./glossary"

describe("glossary", () => {
  it("keeps every definition short, plain and complete", () => {
    expect(TERM_IDS.length).toBeGreaterThanOrEqual(15)
    for (const id of TERM_IDS) {
      const { term, short } = GLOSSARY[id]
      expect(term.length, id).toBeGreaterThan(1)
      expect(short.length, id).toBeGreaterThan(40)
      expect(short.length, id).toBeLessThanOrEqual(260)
      expect(short.endsWith("."), id).toBe(true)
      expect(short, id).not.toMatch(/\s{2,}/)
    }
  })

  it("looks terms up safely", () => {
    expect(isTermId("asn")).toBe(true)
    expect(isTermId("constructor")).toBe(false)
    expect(isTermId("__proto__")).toBe(false)
    expect(lookupTerm("kev")?.term).toBe("KEV")
    expect(lookupTerm("nope")).toBeUndefined()
  })
})

describe("splitTerms", () => {
  it("wraps the first mention of each term and keeps the text intact", () => {
    const text = "2 new campaigns formed. Block the exploit; the campaign uses an exploit kit."
    const parts = splitTerms(text, ["campaign", "exploit"])
    expect(parts.map((p) => (typeof p === "string" ? p : p.text)).join("")).toBe(text)
    const hits = parts.filter((p) => typeof p !== "string")
    expect(hits).toEqual([
      { id: "campaign", text: "campaigns" },
      { id: "exploit", text: "exploit" },
    ])
  })

  it("matches whole words only, case-insensitively where it is safe", () => {
    expect(splitTerms("A CVE and an ASN.")).toEqual([
      "A ",
      { id: "cve", text: "CVE" },
      " and an ",
      { id: "asn", text: "ASN" },
      ".",
    ])
    expect(splitTerms("The nascent exploiter c2x")).toEqual(["The nascent exploiter c2x"])
    // KEV, RCE and C2 are acronyms: lower-case look-alikes are ordinary words.
    expect(splitTerms("kev rce c2")).toEqual(["kev rce c2"])
  })

  it("returns the text alone when nothing matches or the list is empty", () => {
    expect(splitTerms("Nothing here.")).toEqual(["Nothing here."])
    expect(splitTerms("An exploit.", [])).toEqual(["An exploit."])
    expect(splitTerms("")).toEqual([""])
  })
})
