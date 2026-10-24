import { SENSORS, type Sensor } from "@/lib/api"

export interface GlobePalette {
  /** Globe body. */
  sphere: string
  /** Land dots. */
  land: string
  /** Atmosphere rim. */
  rim: string
  /** Home marker. */
  home: string
  sensors: Record<Sensor, string>
}

/** "#5ea6f7" and 0.5 give "rgba(94,166,247,0.5)". Falls back to the input on anything else. */
export function withAlpha(color: string, alpha: number): string {
  const m = /^#([0-9a-f]{6})$/i.exec(color.trim())
  if (!m?.[1]) return color
  const n = parseInt(m[1], 16)
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${alpha})`
}

/** Rough perceived brightness of a #rrggbb colour, 0 to 1. */
export function luminance(hex: string): number {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim())
  if (!m?.[1]) return 0
  const n = parseInt(m[1], 16)
  return (0.2126 * (n >> 16) + 0.7152 * ((n >> 8) & 255) + 0.0722 * (n & 255)) / 255
}

const FALLBACK = "#888888"

/** Reads the design tokens from the document, so the globe follows the theme. */
export function readPalette(root: HTMLElement = document.documentElement): GlobePalette {
  const css = getComputedStyle(root)
  const v = (name: string) => css.getPropertyValue(name).trim() || FALLBACK
  const sensors = Object.fromEntries(SENSORS.map((s) => [s, v(`--sensor-${s}`)])) as Record<
    Sensor,
    string
  >
  return {
    sphere: luminance(v("--bg")) < 0.5 ? v("--bg") : v("--surface-hover"),
    land: v("--fg-subtle"),
    rim: v("--border-strong"),
    home: v("--fg"),
    sensors,
  }
}

/** True when the page asks for no motion. */
export function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches
  )
}

/** True when the browser can create a WebGL context. */
export function webglAvailable(): boolean {
  try {
    const canvas = document.createElement("canvas")
    return !!(canvas.getContext("webgl2") ?? canvas.getContext("webgl"))
  } catch {
    return false
  }
}

/** Test hook: a Playwright init script sets `window.__SUCKERPOT_GLOBE__ = { freeze: true }`. */
export function globeFrozen(): boolean {
  return (
    typeof window !== "undefined" &&
    (window as unknown as { __SUCKERPOT_GLOBE__?: { freeze?: boolean } }).__SUCKERPOT_GLOBE__
      ?.freeze === true
  )
}
