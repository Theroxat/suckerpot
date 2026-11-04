import { expect, test } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

// M30: the community lists, Network tab of Blocklists. Mock data only (src/mocks/network-feed.ts):
// documentation addresses and example.org. `?feed=` picks the starting state, `?network=member`
// makes the system a member.

test("network lists, on", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network")
  await expect(h1(page, "Blocklists")).toBeVisible()
  await expect(page.getByText(/^The SuckerPot network lists/)).toBeVisible()
  await expect(page.getByRole("group", { name: "Outbound list" })).toBeVisible()
  await expect(page.getByRole("list", { name: "Community list entries" })).toBeVisible()
  await settle(page)
  await shootTall(page, "network-feed", info.project.name)
})

test("network lists, member", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network&network=member")
  await expect(page.getByText(/Your sensor helped confirm/)).toBeVisible()
  await expect(page.getByText("You helped").first()).toBeVisible()
  await settle(page)
  await shootTall(page, "network-feed-member", info.project.name)
})

test("network lists, filtered by the URL", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network&list=outbound&tier=high&seen_here=1")
  await expect(
    page.getByText(/Every high-tier outbound entry that also reached this sensor/),
  ).toBeVisible()
  await settle(page)
  await shoot(page, "network-feed-filtered", info.project.name)
})

test("network lists, off", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network&feed=off")
  await expect(page.getByText("The community lists are not fetched here")).toBeVisible()
  await expect(page.getByText("just set NETWORK_FEED_ENABLED=true")).toBeVisible()
  await settle(page)
  await shoot(page, "network-feed-off", info.project.name, true)
})

test("network lists, empty until enough members", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network&feed=empty")
  await expect(page.getByText("Nothing to block yet")).toBeVisible()
  await settle(page)
  await shoot(page, "network-feed-empty", info.project.name, true)
})

test("network lists, stale", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network&feed=stale")
  await expect(page.getByText("Out of date")).toBeVisible()
  await settle(page)
  await shoot(page, "network-feed-stale", info.project.name)
})

test("network lists, how to use drawer", async ({ page }, info) => {
  await page.goto("/defend/blocklists?tab=network")
  await page.getByRole("button", { name: "How to use" }).click()
  const drawer = page.getByRole("dialog")
  await expect(drawer.getByText("Use the lists in your firewall")).toBeVisible()
  await expect(drawer.getByText(/Pick the plain text format/)).toBeVisible()
  await settle(page)
  await shoot(page, "network-feed-howto", info.project.name)
})

test("tabs switch and keep the sensor view intact", async ({ page }) => {
  await page.goto("/defend/blocklists")
  await page.getByRole("tab", { name: "Network" }).click()
  await expect(page).toHaveURL(/tab=network/)
  await expect(page.getByText(/^The SuckerPot network lists/)).toBeVisible()
  await page.getByRole("tab", { name: "This sensor" }).click()
  await expect(page).not.toHaveURL(/tab=/)
  await expect(page.getByRole("list", { name: "Blocklist entries" })).toBeVisible()
})
