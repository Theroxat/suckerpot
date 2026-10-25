import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// P0: the three spaces in the nav and the placeholder pages behind the new routes.
const PLACEHOLDERS: [path: string, title: string][] = [
  ["/campaigns", "Campaigns"],
  ["/campaigns/42", "Campaign"],
  ["/techniques", "Techniques"],
  ["/scripts", "Scripts"],
  ["/scripts/42", "Script"],
  ["/defend/alerts", "Alerts and reports"],
  ["/reports/2026-10-19", "Weekly report"],
]

test("nav spaces and placeholder routes", async ({ page }, info) => {
  for (const [path, title] of PLACEHOLDERS) {
    await page.goto(path)
    await expect(h1(page, title)).toBeVisible()
    await expect(page.getByText("Coming soon", { exact: true })).toBeVisible()
    await settle(page)
  }
  await page.goto("/defend/blocklists")
  await settle(page)
  if (info.project.name.startsWith("mobile")) {
    await page.getByRole("button", { name: "Open navigation" }).click()
    await expect(page.getByRole("dialog")).toBeVisible()
  }
  for (const space of ["Observe", "Understand", "Defend"]) {
    await expect(
      page.getByRole("group", { name: space }).locator("visible=true").first(),
    ).toBeVisible()
  }
  await expect(
    page.getByRole("link", { name: "Activity", exact: true }).locator("visible=true").first(),
  ).toBeVisible()
  await shoot(page, "nav-spaces", info.project.name)
})

test("settings tabs", async ({ page }, info) => {
  await page.goto("/settings")
  await expect(h1(page, "Settings")).toBeVisible()
  await expect(page.getByRole("tab")).toHaveText([
    "General",
    "Keys",
    "Users",
    "Audit",
    "Alert channels",
    "Feeds",
  ])
  await page.getByRole("tab", { name: "Alert channels" }).click()
  await expect(page).toHaveURL(/tab=alerts/)
  await expect(page.getByText("Alert channels are on their way")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-alert-channels", info.project.name)
})
