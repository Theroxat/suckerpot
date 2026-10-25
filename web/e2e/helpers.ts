import { expect, type Page } from "@playwright/test"

/** Shared by every spec in this folder; feature specs import from here instead of copying. */

export const OUT = "screenshots"

export async function settle(page: Page, { skeletons = false } = {}) {
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

export const h1 = (page: Page, name: string) =>
  page.getByRole("heading", { level: 1, name, exact: true })

export async function shoot(page: Page, name: string, projectName: string, fullPage = false) {
  // Focusing controls may have scrolled the window; full-page shots start from the top
  // so the sticky mobile header is not painted mid-page.
  if (fullPage) await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: `${OUT}/${name}-${projectName}.png`, fullPage })
}

/**
 * Full-page shot of a page with a window-virtualized list: grow the viewport to the page height
 * first, so every row is really rendered (a plain full-page capture only paints the rows the
 * virtualizer drew for the original viewport, leaving blank space below them).
 */
export async function shootTall(page: Page, name: string, projectName: string) {
  const original = page.viewportSize()
  if (!original) throw new Error("no viewport")
  await page.evaluate(() => window.scrollTo(0, 0))
  let height = original.height
  for (let i = 0; i < 6; i++) {
    const next = await page.evaluate(() => document.documentElement.scrollHeight)
    if (next <= height) break
    height = next
    await page.setViewportSize({ width: original.width, height })
    await page.evaluate(
      () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))),
    )
  }
  // Chromium repeats content past about 8,192 device pixels: very tall phone shots are taken at
  // CSS pixel scale instead.
  const dpr = await page.evaluate(() => window.devicePixelRatio)
  await page.screenshot({
    path: `${OUT}/${name}-${projectName}.png`,
    scale: height * dpr > 8000 ? "css" : "device",
  })
  await page.setViewportSize(original)
}
