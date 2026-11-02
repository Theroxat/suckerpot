import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M28: first-run setup, the ports tab, the updates card and the version footer.
// Mock data only (src/mocks/setup-wizard.ts): documentation addresses, no real traffic.

const STEPS = [
  { id: "welcome", text: "Selfhostr is a trap" },
  { id: "sensors", text: "Each sensor pretends to be one service" },
  { id: "ports", text: "Attackers only reach a sensor" },
  { id: "vpn", text: "Every lookup and download leaves through a VPN" },
  { id: "self", text: "Selfhostr must know your own address" },
  { id: "reporting", text: "Abuse reports are drafts you send yourself" },
  { id: "alerts", text: "Alerts tell you when something matters" },
  { id: "done", text: "That is everything" },
]

for (const s of STEPS) {
  test(`setup step ${s.id}`, async ({ page }, info) => {
    await page.goto(`/setup?wizard=progress&step=${s.id}`)
    await expect(h1(page, "Set up Selfhostr")).toBeVisible()
    await expect(page.getByRole("heading", { level: 2, name: new RegExp(s.text) })).toBeVisible()
    await settle(page)
    await shoot(page, `setup-${s.id}`, info.project.name, true)
  })
}

test("setup vpn idle", async ({ page }, info) => {
  await page.goto("/setup?wizard=progress&step=vpn&vpn=none")
  await expect(page.getByText("No VPN yet, so nothing leaves this machine.")).toBeVisible()
  await settle(page)
  await shoot(page, "setup-vpn-idle", info.project.name, true)
})

test("setup sensors command", async ({ page }, info) => {
  await page.goto("/setup?wizard=new&step=sensors")
  await page.getByRole("switch", { name: /SIP/ }).click()
  await expect(page.getByLabel("Command to change the sensors")).toContainText(
    "just sensors ssh,telnet,adb,web,docker,redis,sip",
  )
  await settle(page)
  await shoot(page, "setup-sensors-command", info.project.name, true)
})

test("settings ports tab", async ({ page }, info) => {
  await page.goto("/settings?tab=ports")
  await expect(page.getByRole("list", { name: "Sensor ports" })).toBeVisible()
  await settle(page)
  await shoot(page, "settings-ports", info.project.name, true)
})

test("settings updates card", async ({ page }, info) => {
  await page.goto("/settings?update=1")
  await expect(
    page.getByText("Selfhostr v0.9.0 is available. You are running v0.8.0."),
  ).toBeVisible()
  await settle(page)
  await shoot(page, "settings-updates", info.project.name, true)
})
