import { beforeEach, describe, expect, it } from "vitest"
import { BUNDLE_MAX, describeBundle, sampleBundle } from "./sample-bundle"

const sha = (i: number) => i.toString(16).padStart(64, "0")

describe("sample bundle", () => {
  beforeEach(() => sampleBundle.clear())

  it("adds, dedupes and removes", () => {
    expect(sampleBundle.add(sha(1))).toBe(true)
    expect(sampleBundle.add(sha(1))).toBe(true)
    expect(sampleBundle.list()).toEqual([sha(1)])
    sampleBundle.remove(sha(1))
    expect(sampleBundle.list()).toEqual([])
  })

  it("refuses more than the server accepts and anything that is not a sha256", () => {
    for (let i = 0; i < BUNDLE_MAX; i++) expect(sampleBundle.add(sha(i))).toBe(true)
    expect(sampleBundle.add(sha(99))).toBe(false)
    sampleBundle.clear()
    expect(sampleBundle.add("not-a-hash")).toBe(false)
  })

  it("says how much room is left", () => {
    expect(describeBundle(0)).toBe("The sample bundle is empty.")
    expect(describeBundle(1)).toBe("1 sample in the bundle, room for 9 more.")
    expect(describeBundle(10)).toBe("10 samples in the bundle, which is full.")
  })
})
