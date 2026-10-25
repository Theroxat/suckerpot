import {
  countryName,
  formatDuration,
  formatNumber,
  formatRelative,
  maskIp,
  maskIpsInText,
  plural,
} from "./format"

describe("format", () => {
  it("groups thousands", () => {
    expect(formatNumber(18342)).toBe("18,342")
    expect(plural(1, "file")).toBe("1 file")
    expect(plural(2, "file")).toBe("2 files")
  })

  it("formats relative time", () => {
    const now = Date.parse("2026-10-24T18:00:00Z")
    expect(formatRelative("2026-10-24T17:59:58Z", now)).toBe("just now")
    // Clock skew: slightly in the future still reads "just now".
    expect(formatRelative("2026-10-24T18:00:11Z", now)).toBe("just now")
    expect(formatRelative("2026-10-24T17:55:00Z", now)).toBe("5 min. ago")
    expect(formatRelative("2026-10-24T15:00:00Z", now)).toBe("3 hr. ago")
  })

  it("formats durations", () => {
    expect(formatDuration(8)).toBe("8 s")
    expect(formatDuration(100)).toBe("1 min 40 s")
    expect(formatDuration(7500)).toBe("2 h 05 min")
  })

  it("names countries and masks IPs", () => {
    expect(countryName("ch")).toBe("Switzerland")
    expect(countryName("ZZ")).toBeNull()
    expect(countryName(null)).toBeNull()
    expect(maskIp("203.0.113.42")).toBe("203.0.x.x")
    expect(maskIp("2001:db8:1:2::5")).toBe("2001:db8:x::x")
    expect(maskIpsInText("wget http://198.51.100.7/x.sh; ping 192.0.2.1")).toBe(
      "wget http://198.51.x.x/x.sh; ping 192.0.x.x",
    )
    expect(maskIpsInText("PHP 8.3.12 on Ubuntu")).toBe("PHP 8.3.12 on Ubuntu")
  })
})
