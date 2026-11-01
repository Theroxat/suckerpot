import { expect, test } from "@playwright/test"
import { h1, settle, shoot } from "./helpers"

// M26/M27: results of abuse reports, submissions, replies. Mock data only.

test("results page", async ({ page }, info) => {
  await page.goto("/defend/results")
  await expect(h1(page, "Results")).toBeVisible()
  await expect(page.getByText("Did anyone answer?")).toBeVisible()
  await expect(page.getByRole("table", { name: "Tracked targets" })).toBeVisible()
  await settle(page)
  await shoot(page, "results", info.project.name, true)
})

test("results target", async ({ page }, info) => {
  await page.goto("/defend/results/targets/4")
  await expect(page.getByText("Timeline", { exact: true })).toBeVisible()
  await settle(page)
  await shoot(page, "results-target", info.project.name, true)
})

test("submissions", async ({ page }, info) => {
  await page.goto("/defend/submissions")
  await expect(h1(page, "Submissions")).toBeVisible()
  await expect(page.getByText("To review").first()).toBeVisible()
  await settle(page)
  await shoot(page, "submissions", info.project.name, true)
})

test("outcome card and replies on a sent report", async ({ page }, info) => {
  await page.goto("/defend/abuse/3c4d5e6f-7a8b-4c9d-8e0f-6f7a8b9c0d06")
  await expect(page.getByText("Outcome", { exact: true })).toBeVisible()
  await expect(page.getByRole("list", { name: "Replies" })).toBeVisible()
  await settle(page)
  await shoot(page, "abuse-outcome", info.project.name, true)
})

test("settings replies and abuse.ch cards", async ({ page }, info) => {
  await page.goto("/settings?tab=reporting")
  await expect(page.getByText("Auth-Key")).toBeVisible()
  await expect(page.getByText("Read replies from this mailbox")).toBeVisible()
  await settle(page)
  await shoot(page, "settings-replies-abusech", info.project.name, true)
})
