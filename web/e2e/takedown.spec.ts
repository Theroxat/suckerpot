import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M27: takedown views (URL and host re-checks, per-provider stats). Mock data only
// (src/mocks/takedown.ts).

test("results filtered to URLs", async ({ page }, info) => {
  await page.goto("/defend/results?kind=url")
  await expect(h1(page, "Results")).toBeVisible()
  await expect(page.getByRole("button", { name: "Remove the kind filter url" })).toBeVisible()
  await expect(page.getByRole("table", { name: "Tracked targets" })).toBeVisible()
  await settle(page)
  await shoot(page, "results-urls", info.project.name, true)
})

test("results filtered to hosts", async ({ page }, info) => {
  await page.goto("/defend/results?kind=host")
  await expect(page.getByRole("button", { name: "Remove the kind filter host" })).toBeVisible()
  await expect(page.getByRole("table", { name: "Tracked targets" })).toBeVisible()
  await settle(page)
  await shoot(page, "results-hosts", info.project.name, true)
})

test("per-provider takedown stats", async ({ page }, info) => {
  await page.goto("/defend/results")
  const providers = page.getByRole("table", { name: "Providers that received reports" })
  await expect(providers).toBeVisible()
  await expect(providers.getByRole("columnheader", { name: /Median takedown/ })).toBeVisible()
  await settle(page)
  await providers.scrollIntoViewIfNeeded()
  await shoot(page, "results-providers", info.project.name)
})

test("URL target re-check", async ({ page }, info) => {
  await page.goto("/defend/results/targets/6")
  await expect(page.getByText("We only re-check this exact address")).toBeVisible()
  await page.getByRole("button", { name: "Check now" }).click()
  await settle(page)
  await shoot(page, "takedown-url", info.project.name, true)
})

test("host target that changed", async ({ page }, info) => {
  await page.goto("/defend/results/targets/4")
  await expect(page.getByText("Timeline", { exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "Stop tracking" })).toBeVisible()
  await settle(page)
  await shoot(page, "takedown-host", info.project.name, true)
})
