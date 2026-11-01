import { describe, expect, it } from "vitest"
import {
  describePort,
  describePorts,
  describeProgress,
  firstOpenStep,
  normalizeProgress,
  orderedSensors,
  sensorsCommand,
  setCommand,
  stepIndex,
  takeSetupOffer,
  WIZARD_STEPS,
  type PortItem,
} from "./setup-wizard"

const item = (over: Partial<PortItem>): PortItem => ({
  sensor: "ssh",
  label: "SSH",
  enabled: true,
  protocols: ["tcp"],
  external_port: 22,
  host_port: 2222,
  env_var: "SSH_HOST_PORT",
  state: "receiving",
  last_event_at: null,
  ...over,
})

describe("progress", () => {
  it("only shows the setup while it is new or in progress", () => {
    expect(normalizeProgress({ state: "new", steps: {}, show: true }).show).toBe(true)
    expect(normalizeProgress({ state: "finished", steps: {}, show: true }).show).toBe(false)
    expect(normalizeProgress({}).state).toBe("finished")
  })

  it("drops unknown step statuses", () => {
    const p = normalizeProgress({ state: "in_progress", steps: { a: "done", b: "x" }, show: true })
    expect(p.steps).toEqual({ a: "done" })
  })

  it("opens at the first step that is neither done nor skipped", () => {
    expect(firstOpenStep({ steps: {} }, WIZARD_STEPS)).toBe(0)
    expect(firstOpenStep({ steps: { welcome: "done", sensors: "skipped" } }, WIZARD_STEPS)).toBe(2)
    expect(stepIndex("vpn", WIZARD_STEPS)).toBe(3)
    expect(stepIndex("nope", WIZARD_STEPS)).toBe(0)
  })

  it("counts the steps that are done", () => {
    const p = normalizeProgress({
      state: "in_progress",
      steps: { welcome: "done", sensors: "skipped" },
      show: true,
    })
    expect(describeProgress(p, WIZARD_STEPS)).toBe("2 of 8 setup steps are done.")
  })

  it("keeps a slot for the network step, before the last one", () => {
    const ids = WIZARD_STEPS.map((s) => s.id)
    expect(ids.indexOf("network")).toBe(ids.length - 2)
    expect(ids.at(-1)).toBe("done")
  })
})

describe("ports", () => {
  it("writes the protocol and the plain port number", () => {
    expect(describePort(item({}))).toBe("TCP 22")
    expect(describePort(item({ protocols: ["udp", "tcp"], external_port: 5060 }))).toBe(
      "UDP + TCP 5060",
    )
    expect(describePort(item({ external_port: 3306 }))).toBe("TCP 3306")
  })

  it("says what is left to do", () => {
    expect(describePorts([item({ enabled: false, state: "off" })])).toMatch(
      /No sensor is switched on/,
    )
    expect(describePorts([item({}), item({ sensor: "web" })])).toBe(
      "All 2 enabled sensors are receiving traffic.",
    )
    expect(describePorts([item({ state: "waiting" })])).toMatch(/had a connection yet/)
    expect(
      describePorts([
        item({}),
        item({ sensor: "web", state: "waiting" }),
        item({ enabled: false }),
      ]),
    ).toBe(
      "1 of 2 enabled sensors are receiving traffic, 1 is still waiting for a first connection.",
    )
  })
})

describe("host commands", () => {
  it("lists sensors in registry order and ignores unknown names", () => {
    expect(orderedSensors(["web", "ssh", "nope"])).toEqual(["ssh", "web"])
    expect(sensorsCommand(["web", "telnet", "ssh"])).toBe("just sensors ssh,telnet,web")
    expect(sensorsCommand([])).toBe("just sensors")
    expect(setCommand("ABUSE_REPORTS_ENABLED", "true")).toBe("just set ABUSE_REPORTS_ENABLED=true")
  })
})

describe("takeSetupOffer", () => {
  it("is true once per session", () => {
    const store = new Map<string, string>()
    const storage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
    } as unknown as Storage
    expect(takeSetupOffer(storage)).toBe(true)
    expect(takeSetupOffer(storage)).toBe(false)
  })
})
