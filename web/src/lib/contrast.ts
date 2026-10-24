/** WCAG 2.x contrast helpers, used by the token tests and the styleguide. */

export type Rgb = readonly [number, number, number]

export function parseHex(hex: string): Rgb {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim())
  if (!m?.[1]) throw new Error(`not a 6-digit hex colour: ${hex}`)
  const n = Number.parseInt(m[1], 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

function channel(c: number): number {
  const s = c / 255
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
}

export function luminance([r, g, b]: Rgb): number {
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

export function contrastRatio(a: Rgb, b: Rgb): number {
  const la = luminance(a)
  const lb = luminance(b)
  const [hi, lo] = la > lb ? [la, lb] : [lb, la]
  return (hi + 0.05) / (lo + 0.05)
}

/** Composite `top` at `alpha` (0..1) over an opaque `bottom`, like color-mix(). */
export function blend(top: Rgb, bottom: Rgb, alpha: number): Rgb {
  const mix = (a: number, b: number) => Math.round(a * alpha + b * (1 - alpha))
  return [mix(top[0], bottom[0]), mix(top[1], bottom[1]), mix(top[2], bottom[2])]
}

/** Extract `--name: #hex;` declarations from the first block matching `selector`. */
export function readTokenBlock(css: string, selectorStart: string): Record<string, string> {
  const start = css.indexOf(selectorStart)
  if (start < 0) throw new Error(`selector not found: ${selectorStart}`)
  const open = css.indexOf("{", start)
  const close = css.indexOf("}", open)
  const body = css.slice(open + 1, close)
  const out: Record<string, string> = {}
  for (const m of body.matchAll(/--([a-z0-9-]+):\s*([^;]+);/gi)) {
    if (m[1] && m[2]) out[m[1]] = m[2].trim()
  }
  return out
}
