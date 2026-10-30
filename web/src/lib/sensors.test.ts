import { describe, expect, it } from "vitest"
import {
  FAMILY_META,
  SENSOR_FAMILIES,
  SENSOR_META,
  SENSORS,
  exactFamily,
  formatSensors,
  parseSensors,
  sensorSetLabel,
  sensorSetPhrase,
  sensorsHref,
  sumByFamily,
} from "./sensors"

describe("sensor registry", () => {
  it("knows the twelve API sensor names", () => {
    expect([...SENSORS].sort()).toEqual(
      [
        "adb",
        "docker",
        "mssql",
        "mysql",
        "rdp",
        "redis",
        "sip",
        "smb",
        "ssh",
        "synology",
        "telnet",
        "web",
      ].sort(),
    )
  })
  it("puts every sensor in exactly one family, in registry order", () => {
    const members = SENSOR_FAMILIES.flatMap((f) => FAMILY_META[f].sensors)
    expect(members).toEqual([...SENSORS])
    for (const s of SENSORS) expect(FAMILY_META[SENSOR_META[s].family].sensors).toContain(s)
  })
  it("gives every sensor its own icon and label, so colour is never needed", () => {
    expect(new Set(SENSORS.map((s) => SENSOR_META[s].icon)).size).toBe(SENSORS.length)
    expect(new Set(SENSORS.map((s) => SENSOR_META[s].label)).size).toBe(SENSORS.length)
  })
  it("colours sensors by family", () => {
    expect(SENSOR_META.ssh.text).toBe(SENSOR_META.adb.text)
    expect(SENSOR_META.redis.cssVar).toBe("var(--family-data)")
    expect(SENSOR_META.redis.shadeVar).toBe("var(--sensor-redis)")
  })
})

describe("?sensor= URL filter", () => {
  it("parses a comma list, ignoring unknown names and duplicates", () => {
    expect(parseSensors("telnet,ssh,nope,ssh")).toEqual(["ssh", "telnet"])
    expect(parseSensors("web")).toEqual(["web"])
    expect(parseSensors(null)).toEqual([])
    expect(parseSensors("")).toEqual([])
  })
  it("formats in registry order, and drops the filter for none or all", () => {
    expect(formatSensors(["redis", "ssh"])).toBe("ssh,redis")
    expect(formatSensors([])).toBeNull()
    expect(formatSensors([...SENSORS])).toBeNull()
    expect(sensorsHref(["smb"])).toBe("/attacks?sensor=smb")
    expect(sensorsHref([])).toBe("/attacks")
  })
})

describe("selection names", () => {
  it("names one sensor, a few, a whole family or a count", () => {
    expect(sensorSetLabel([])).toBe("All sensors")
    expect(sensorSetLabel(["ssh"])).toBe("SSH")
    expect(sensorSetLabel(["ssh", "web"])).toBe("SSH and Web")
    expect(sensorSetLabel(["redis", "mysql", "mssql"])).toBe("Databases")
    expect(sensorSetLabel(["ssh", "web", "rdp", "smb"])).toBe("4 sensors")
    expect(sensorSetPhrase(["ssh", "telnet", "adb"])).toBe("the remote shells")
    expect(exactFamily(["web", "docker", "synology"])).toBe("web")
    expect(exactFamily(["web", "docker"])).toBeNull()
    expect(exactFamily(["web", "ssh"])).toBeNull()
  })
  it("sums per-sensor counts into families", () => {
    expect(sumByFamily({ ssh: 3, adb: 2, redis: 5, sip: 1, unknown: 9 })).toEqual({
      shell: 5,
      web: 0,
      data: 5,
      windows: 1,
    })
  })
})
