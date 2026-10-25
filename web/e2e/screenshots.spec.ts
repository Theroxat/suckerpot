import { expect, test, type Page } from "@playwright/test"

const OUT = "screenshots"

async function settle(page: Page, { skeletons = false } = {}) {
  await page.waitForLoadState("networkidle")
  await page.evaluate(() => document.fonts.ready)
  // Skeletons are gone once data is in (the styleguide shows them on purpose).
  await expect(page.locator('[role="status"][aria-label="Loading page"]')).toHaveCount(0)
  if (!skeletons) await expect(page.locator('[role="status"][aria-label="Loading"]')).toHaveCount(0)
  // No horizontal page scroll, at any width.
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow, "page scrolls horizontally").toBeLessThanOrEqual(0)
}

const h1 = (page: Page, name: string) => page.getByRole("heading", { level: 1, name, exact: true })

async function shoot(page: Page, name: string, projectName: string, fullPage = false) {
  // Focusing controls may have scrolled the window; full-page shots start from the top
  // so the sticky mobile header is not painted mid-page.
  if (fullPage) await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: `${OUT}/${name}-${projectName}.png`, fullPage })
}

test("styleguide", async ({ page }, info) => {
  // A very long page plus one crop per section: slow on software-rendered mobile runs.
  test.setTimeout(150_000)
  await page.goto("/styleguide")
  await expect(h1(page, "Styleguide")).toBeVisible()
  await settle(page, { skeletons: true })
  await shoot(page, "styleguide", info.project.name, true)
  // Per-section crops make the long page reviewable at full resolution.
  for (const id of [
    "colour",
    "sensors",
    "severity",
    "type",
    "space",
    "motion",
    "components",
    "data",
    "charts",
    "trends",
    "states",
  ]) {
    await page.locator(`section#${id}`).screenshot({
      path: `${OUT}/sections/styleguide-${id}-${info.project.name}.png`,
    })
  }
})

test("attacks", async ({ page }, info) => {
  await page.goto("/attacks")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await settle(page)
  await shoot(page, "attacks", info.project.name)

  await page.goto("/attacks?sensor=web")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await settle(page)
  await shoot(page, "attacks-web", info.project.name)

  // M9: a whole family selected, then the multi-select filter open (keyboard-driven).
  await page.goto("/attacks?sensor=redis,mysql,mssql")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await settle(page)
  await page.getByRole("button", { name: /^Sensors/ }).click()
  const options = page.getByRole("listbox", { name: "Sensors" })
  await expect(options).toBeVisible()
  await page.keyboard.type("ss")
  await expect(options.getByRole("option")).not.toHaveCount(0)
  await page.keyboard.press("Control+a")
  await page.keyboard.press("Backspace")
  await expect(options.getByRole("option", { name: /SMB/ })).toBeVisible()
  await shoot(page, "attacks-filter-open", info.project.name)
})

test("session detail", async ({ page }, info) => {
  await page.goto("/attacks")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await settle(page)
  // Open the first session that ran commands (has a warning/severe marker).
  const row = page.getByRole("listitem").filter({ hasText: "ran" }).first()
  await row.locator("a").first().click()
  await expect(page.getByRole("list", { name: "Events" })).toBeVisible()
  await settle(page)
  await shoot(page, "session", info.project.name, true)
})

test("shell", async ({ page }, info) => {
  await page.goto("/overview")
  await expect(h1(page, "Overview")).toBeVisible()
  await settle(page)
  await shoot(page, "overview", info.project.name, true)

  // Every page is real since M8: the shell's empty state is the 404 page.
  await page.goto("/no-such-page")
  await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible()
  await settle(page)
  await shoot(page, "not-found", info.project.name)

  if (info.project.name.startsWith("mobile")) {
    await page.getByRole("button", { name: "Open navigation" }).click()
    await expect(page.getByRole("dialog")).toBeVisible()
    await shoot(page, "nav-open", info.project.name)
  }
})

test("live", async ({ page }, info) => {
  // Software-rendered WebGL for the globe view: slower than the other pages.
  test.setTimeout(240_000)
  // Test hook: freeze motion (no dashes, pulses, rotation) so the shots are deterministic.
  await page.addInitScript(() => {
    ;(window as unknown as { __SUCKERPOT_GLOBE__: { freeze: boolean } }).__SUCKERPOT_GLOBE__ = {
      freeze: true,
    }
  })
  // M9: the flat map is the default view.
  await page.goto("/live")
  await expect(h1(page, "Live")).toBeVisible()
  await expect(page.getByRole("group", { name: /Map of attack origins/ })).toBeVisible()
  // Backfill (50 events) arrives over the mocked WebSocket.
  await expect(page.getByRole("list", { name: "Live events" })).toBeVisible()
  await expect(page.getByRole("listitem").first()).toBeVisible()
  await expect(page.getByRole("list", { name: /Top sources/ })).toBeVisible()
  await settle(page)
  await shoot(page, "live", info.project.name, true)

  await page.goto("/live?view=globe")
  await expect(page.getByRole("img", { name: /Globe of recent attack origins/ })).toBeVisible()
  await expect(page.locator("canvas").first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole("listitem").first()).toBeVisible()
  await settle(page)
  await page.waitForTimeout(1_500)
  await shoot(page, "live-globe", info.project.name)

  await page.goto("/live?sensor=web&view=map")
  await expect(page.getByRole("list", { name: "Live events" })).toBeVisible()
  await settle(page)
  await shoot(page, "live-web", info.project.name)

  if (info.project.name.startsWith("desktop")) {
    await page.setViewportSize({ width: 1920, height: 1080 })
    for (const view of ["map", "globe"] as const) {
      await page.goto(`/live?view=${view}`)
      await expect(page.getByRole("listitem").first()).toBeVisible()
      if (view === "globe") await expect(page.locator("canvas").first()).toBeVisible()
      await settle(page)
      await page.waitForTimeout(view === "globe" ? 1_500 : 300)
      await shoot(page, `live-1920-${view}`, info.project.name)
    }
  }

  // The "World" preset (remembered on this browser afterwards, so it goes last).
  await page.goto("/live?view=map")
  await expect(page.getByRole("listitem").first()).toBeVisible()
  await settle(page)
  await page.getByRole("button", { name: "World", exact: true }).click()
  await page.waitForTimeout(300)
  await shoot(page, "live-world", info.project.name)
})

test("screenshot mode masks every address", async ({ page }, info) => {
  await page.goto("/attacks?mask=1")
  await expect(page.getByRole("list", { name: "Sessions" })).toBeVisible()
  await settle(page)
  // No full documentation address may remain visible anywhere on the page.
  const text = await page.locator("main").innerText()
  expect(text).not.toMatch(/\b(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/)
  await shoot(page, "attacks-masked", info.project.name)

  // The setting persists without the flag.
  await page.goto("/live")
  await expect(page.getByRole("listitem").first()).toBeVisible()
  await settle(page)
  const live = await page.locator("main").innerText()
  expect(live).not.toMatch(/\b(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/)
  await shoot(page, "live-masked", info.project.name)
})

// Terminal replay (M5): a recorded SSH session, paused mid-way.
test("session replay", async ({ page }, info) => {
  await page.goto("/attacks/ReplayDemo01")
  const replay = page.getByRole("group", { name: /Terminal replay/ })
  await expect(replay).toBeVisible()
  await expect(page.getByRole("list", { name: "Events" })).toBeVisible()
  // Reduced motion is on: nothing autoplays. Arrow keys skip 5 s each.
  await replay.focus()
  for (let i = 0; i < 6; i++) await page.keyboard.press("ArrowRight")
  // Narrow screens wrap and scroll the terminal, so only assert on a short, always-visible token.
  await expect(page.locator(".xterm-rows")).toContainText("srv-web01")
  await page.locator("button[aria-label='Play']").focus()
  await settle(page)
  await shoot(page, "session-replay", info.project.name, true)
})

test("session replay reconstructed from commands", async ({ page }, info) => {
  await page.goto("/attacks/CmdsOnlyDemo")
  await expect(page.getByText("Reconstructed from commands")).toBeVisible()
  const replay = page.getByRole("group", { name: /Terminal replay/ })
  await replay.focus()
  for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowRight")
  await expect(page.locator(".xterm-rows")).toContainText("uname -a")
  await settle(page)
  await shoot(page, "session-replay-reconstructed", info.project.name)
})

test("session replay masks addresses in the terminal", async ({ page }, info) => {
  await page.goto("/attacks/ReplayDemo01?mask=1")
  const replay = page.getByRole("group", { name: /Terminal replay/ })
  await expect(replay).toBeVisible()
  await replay.focus()
  for (let i = 0; i < 6; i++) await page.keyboard.press("ArrowRight")
  if (info.project.name.startsWith("desktop")) {
    await expect(page.locator(".xterm-rows")).toContainText("198.51.xxx.xx")
  }
  const rows = await page.locator(".xterm-rows").innerText()
  expect(rows).not.toMatch(/\b(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/)
  const main = await page.locator("main").innerText()
  expect(main).not.toMatch(/\b(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/)
})

test("overview charts", async ({ page }, info) => {
  await page.goto("/overview")
  await expect(h1(page, "Overview")).toBeVisible()
  await expect(page.getByRole("img", { name: /Stacked bar chart/ })).toBeVisible()
  await expect(page.locator(".recharts-bar-rectangle").first()).toBeVisible()
  await settle(page)
  await shoot(page, "overview-charts", info.project.name, true)

  // M9: drill down from families to one shade per sensor.
  await page.goto("/overview?split=sensor")
  await expect(page.getByRole("img", { name: /events per hour by sensor\./ })).toBeVisible()
  await expect(page.locator(".recharts-bar-rectangle").first()).toBeVisible()
  await settle(page)
  await page
    .getByRole("img", { name: /Stacked bar chart/ })
    .locator("xpath=ancestor::*[@data-slot='card'][1]")
    .screenshot({ path: `${OUT}/sections/overview-split-sensor-${info.project.name}.png` })
})

test("attackers", async ({ page }, info) => {
  await page.goto("/attackers")
  await expect(h1(page, "Attackers")).toBeVisible()
  await expect(page.getByRole("list", { name: "Attackers" })).toBeVisible()
  await settle(page)
  await shoot(page, "attackers", info.project.name)

  await page.goto("/attackers?sort=sessions&sensor=ssh")
  await expect(page.getByRole("list", { name: "Attackers" })).toBeVisible()
  await settle(page)
  await shoot(page, "attackers-sorted", info.project.name)

  await page.goto("/attackers?view=asns")
  await expect(page.getByRole("list", { name: "Networks" })).toBeVisible()
  await settle(page)
  await shoot(page, "attackers-asns", info.project.name)
})

test("attacker detail", async ({ page }, info) => {
  await page.goto("/attackers/203.0.113.77")
  await expect(h1(page, "203.0.113.77")).toBeVisible()
  await expect(page.getByRole("list", { name: "Recent sessions" })).toBeVisible()
  await settle(page)
  await shoot(page, "attacker-detail", info.project.name, true)

  await page.goto("/attackers/203.0.113.77?mask=1")
  await expect(h1(page, "203.0.x.x")).toBeVisible()
  await settle(page)
  const text = await page.locator("main").innerText()
  expect(text).not.toMatch(/\b(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/)
  await page.goto("/attackers?mask=0")
})

// M7: Trends and Malware.
test("trends", async ({ page }, info) => {
  await page.goto("/trends")
  await expect(h1(page, "Trends")).toBeVisible()
  await expect(page.getByRole("img", { name: /Heatmap of events/ })).toBeVisible()
  await expect(page.getByRole("img", { name: /Stacked bar chart of tagged events/ })).toBeVisible()
  await expect(page.getByRole("list", { name: "New values" })).toBeVisible()
  await settle(page)
  await shoot(page, "trends", info.project.name, true)

  await page.goto("/trends?days=30&sensor=ssh&field=password")
  await expect(h1(page, "Trends")).toBeVisible()
  await expect(page.getByRole("list", { name: "New values" })).toBeVisible()
  await settle(page)
  await shoot(page, "trends-30d", info.project.name, true)
})

test("malware", async ({ page }, info) => {
  await page.goto("/malware")
  await expect(h1(page, "Malware")).toBeVisible()
  await expect(page.getByRole("list", { name: "Download URLs" })).toBeVisible()
  // Malware URLs are text, never links.
  await expect(page.getByRole("list", { name: "Download URLs" }).locator("a")).toHaveCount(0)
  await settle(page)
  await shoot(page, "malware", info.project.name)

  await page.goto("/malware?mask=1")
  await expect(page.getByRole("list", { name: "Download URLs" })).toBeVisible()
  await settle(page)
  const text = await page.locator("main").innerText()
  expect(text).not.toMatch(/\b(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b/)
  await page.goto("/malware?mask=0")

  const first = page.getByRole("list", { name: "Download URLs" }).getByRole("button").first()
  await first.click()
  await expect(page.getByRole("dialog")).toBeVisible()
  await expect(page.getByText("Payload fetching is off").first()).toBeVisible()
  // The drawer loads its own detail: wait for its skeleton to go.
  await expect(page.getByRole("dialog").getByRole("status", { name: "Loading" })).toHaveCount(0)
  await shoot(page, "malware-detail", info.project.name)
})

// Login (M8): the mock build treats everyone as signed in, the form itself is always reachable.
test("login", async ({ page }, info) => {
  await page.goto("/login")
  await expect(h1(page, "Sign in")).toBeVisible()
  await settle(page)
  await shoot(page, "login", info.project.name)

  await page.getByLabel("Username").fill("admin")
  await page.getByLabel("Password").fill("wrong")
  await page.getByRole("button", { name: "Sign in" }).click()
  await expect(page.getByRole("alert")).toContainText("Invalid username or password")
  await settle(page)
  await shoot(page, "login-error", info.project.name)
})

// Settings (M8): read-only status of sensors, enrichment, retention and storage.
test("settings", async ({ page }, info) => {
  await page.goto("/settings")
  await expect(h1(page, "Settings")).toBeVisible()
  await expect(page.getByRole("list", { name: "Sensors" })).toBeVisible()
  await expect(page.getByRole("meter").first()).toBeVisible()
  await settle(page)
  await shoot(page, "settings", info.project.name, true)
})

// Settings (M11): enrichment API keys. Mock data only: the typed key and password are fake.
test("settings keys", async ({ page }, info) => {
  await page.goto("/settings")
  const keys = page.getByRole("list", { name: "API keys" })
  await expect(keys).toBeVisible()
  await settle(page)
  await keys.scrollIntoViewIfNeeded()
  await shoot(page, "settings-keys", info.project.name)

  // Set a MaxMind key: a wrong password first, then the right one.
  await page.getByRole("button", { name: "Set the MaxMind GeoLite2 key" }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog).toBeVisible()
  await dialog.getByLabel("Account ID").fill("424242")
  await dialog.getByLabel("Licence key").fill("placeholder-licence-key-0001")
  await dialog.getByLabel("Your password").fill("wrong")
  await dialog.getByRole("button", { name: "Save key" }).click()
  await expect(dialog.getByText("That password is not correct.")).toBeVisible()
  await shoot(page, "settings-key-dialog", info.project.name)
  await dialog.getByLabel("Your password").fill("a-demo-password")
  await dialog.getByRole("button", { name: "Save key" }).click()
  await expect(dialog).toBeHidden()
  const maxmind = keys.getByRole("listitem").filter({ hasText: "MaxMind GeoLite2" })
  await expect(maxmind.getByText("Set in Settings")).toBeVisible()
  await expect(maxmind.getByText("0001")).toBeVisible()

  // Test the GreyNoise key: pending, then the outcome.
  const gn = keys.getByRole("listitem").filter({ hasText: "GreyNoise Community" })
  await gn.getByRole("button", { name: "Test the GreyNoise Community key" }).click()
  const testButton = gn.getByRole("button", { name: "Test the GreyNoise Community key" })
  await expect(testButton).toBeDisabled()
  await expect(testButton).toBeEnabled()
  await expect(gn.getByText("The provider accepted the key.")).toBeVisible()
  await settle(page)
  await keys.scrollIntoViewIfNeeded()
  await shoot(page, "settings-keys-after", info.project.name)
})

test("settings keys disabled", async ({ page }, info) => {
  await page.goto("/settings?keys=off")
  const keys = page.getByRole("list", { name: "API keys" })
  await expect(keys).toBeVisible()
  await expect(page.getByRole("button", { name: "Set the AbuseIPDB key" })).toBeDisabled()
  await settle(page)
  await keys.scrollIntoViewIfNeeded()
  await shoot(page, "settings-keys-disabled", info.project.name)
})
