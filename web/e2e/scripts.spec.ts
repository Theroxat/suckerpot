import { expect, test } from "@playwright/test"
import { h1, settle, shoot, shootTall } from "./helpers"

test("scripts library", async ({ page }, info) => {
  await page.goto("/scripts")
  await expect(h1(page, "Scripts")).toBeVisible()
  await expect(page.getByRole("list", { name: "Scripts" })).toBeVisible()
  await settle(page)
  await shootTall(page, "scripts", info.project.name)

  await page.goto("/scripts?view=new")
  await expect(page.getByRole("list", { name: "Scripts" })).toBeVisible()
  await settle(page)
  await shoot(page, "scripts-new", info.project.name)

  await page.goto("/scripts?technique=T1105&sensor=ssh")
  await expect(page.getByRole("list", { name: "Scripts" })).toBeVisible()
  await settle(page)
  await shoot(page, "scripts-filtered", info.project.name)
})

test("script detail", async ({ page }, info) => {
  await page.goto("/scripts/1")
  await expect(h1(page, "Script 1")).toBeVisible()
  await expect(page.getByRole("list", { name: "Commands with explanations" })).toBeVisible()
  await expect(page.getByText("AI-generated, may be wrong").first()).toBeVisible()
  await settle(page)
  await shootTall(page, "script-detail", info.project.name)

  // A script without an AI explanation: ask for one.
  await page.goto("/scripts/2")
  await expect(h1(page, "Script 2")).toBeVisible()
  const ask = page.getByRole("button", { name: "Explain now" })
  await expect(ask).toBeVisible()
  await settle(page)
  await shoot(page, "script-detail-explain", info.project.name, true)
  await ask.click()
  await expect(page.getByRole("button", { name: "Explaining…" })).toBeVisible()
  await expect(page.getByText("AI-generated, may be wrong").first()).toBeVisible({
    timeout: 15_000,
  })
  await shoot(page, "script-detail-ai", info.project.name, true)

  await page.goto("/scripts/9999")
  await expect(page.getByText("This script is not in the library")).toBeVisible()
})
