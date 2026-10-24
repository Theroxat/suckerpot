import type { ITheme } from "@xterm/xterm"

/**
 * The replay terminal is always dark, in both app themes: a terminal is a
 * terminal, and it keeps attacker output visually apart from the UI.
 *
 * Its ANSI palette is deliberately muted and independent of the semantic
 * tokens: attacker-controlled colours must never borrow the meaning of a
 * sensor hue or of "severe" red. Every colour is AA (>= 4.5:1) on the
 * background; see terminal-theme.test.ts.
 */
export const TERMINAL_BG = "#0b0c0e"

export const TERMINAL_THEME: ITheme = {
  background: TERMINAL_BG,
  foreground: "#d4d6da",
  cursor: "#d4d6da",
  cursorAccent: TERMINAL_BG,
  selectionBackground: "#34373e",
  scrollbarSliderBackground: "rgba(255, 255, 255, 0.10)",
  scrollbarSliderHoverBackground: "rgba(255, 255, 255, 0.18)",
  scrollbarSliderActiveBackground: "rgba(255, 255, 255, 0.24)",
  black: "#7d808a",
  red: "#c99a9a",
  green: "#9cbfa3",
  yellow: "#cdbb8e",
  blue: "#9aaecb",
  magenta: "#bba6c9",
  cyan: "#93bdb9",
  white: "#b9bcc3",
  brightBlack: "#8d909a",
  brightRed: "#d6abab",
  brightGreen: "#adcbb3",
  brightYellow: "#d8c9a2",
  brightBlue: "#acbdd6",
  brightMagenta: "#c8b6d4",
  brightCyan: "#a6cac6",
  brightWhite: "#eceef1",
}
