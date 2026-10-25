import { defineConfig } from "@playwright/test"

const PORT = 4173

/**
 * Screenshot runs only (no functional e2e yet). Serves the mock build
 * (`pnpm build:mock`) with `vite preview`, so no API is needed.
 */
export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  fullyParallel: true,
  reporter: [["list"]],
  timeout: 60_000,
  // Lazy chunks on a cold preview server can take a few seconds on first use.
  expect: { timeout: 15_000 },
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    reducedMotion: "reduce",
    timezoneId: "Europe/Zurich",
    locale: "en-US",
  },
  projects: [
    {
      name: "desktop-dark",
      use: { viewport: { width: 1440, height: 900 }, colorScheme: "dark" },
    },
    {
      name: "desktop-light",
      use: { viewport: { width: 1440, height: 900 }, colorScheme: "light" },
    },
    {
      name: "mobile-dark",
      use: {
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 2,
        isMobile: true,
        hasTouch: true,
        colorScheme: "dark",
      },
    },
    {
      name: "mobile-light",
      use: {
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 2,
        isMobile: true,
        hasTouch: true,
        colorScheme: "light",
      },
    },
  ],
  webServer: {
    command: `pnpm preview:mock --host 127.0.0.1`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
})
