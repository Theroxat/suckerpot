import { expect, test } from "@playwright/test"
import { settle, shoot } from "./helpers"

// M23: Settings, VPN tab. Mock data only (src/mocks/vpn.ts): documentation addresses, fake keys.

test("settings vpn from .env", async ({ page }, info) => {
  await page.goto("/settings?tab=vpn")
  await expect(
    page.getByText("Traffic leaves through 203.0.113.7 (settings from .env)."),
  ).toBeVisible()
  await expect(page.getByLabel("WireGuard configuration file")).toBeAttached()
  await settle(page)
  await shoot(page, "settings-vpn", info.project.name, true)
})

test("settings vpn upload needs trust", async ({ page }, info) => {
  await page.goto("/settings?tab=vpn&vpn=upload")
  await expect(
    page.getByText("The gate is closed: the new exit 198.51.100.20 is not trusted yet."),
  ).toBeVisible()
  await expect(page.getByRole("list", { name: "Trusted exits" })).toBeVisible()
  await settle(page)
  await shoot(page, "settings-vpn-trust", info.project.name, true)
  await page.getByRole("button", { name: "Trust 198.51.100.0/24" }).click()
  await expect(page.getByRole("dialog")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-vpn-trust-dialog", info.project.name)
  await page.getByLabel("Your password").fill("demo")
  await page.getByRole("dialog").getByRole("button", { name: "Trust 198.51.100.0/24" }).click()
  await expect(page.getByText(/Traffic leaves through 198\.51\.100\.20/)).toBeVisible()
})
