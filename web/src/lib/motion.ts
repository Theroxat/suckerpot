/**
 * Entrance motion can be frozen without the visitor's reduced-motion setting: screenshots and
 * tests set `window.__SUCKERPOT_MOTION__ = { freeze: true }` (the Live map's older
 * `__SUCKERPOT_MAP__` hook counts too) or open a page with `?motion=off`. The CSS reacts to
 * `data-motion="off"` on the root element; `prefers-reduced-motion` needs no help.
 */
interface MotionHooks {
  __SUCKERPOT_MOTION__?: { freeze?: boolean }
  __SUCKERPOT_MAP__?: { freeze?: boolean }
}

export function motionFrozen(): boolean {
  const w = window as unknown as MotionHooks
  return (
    w.__SUCKERPOT_MOTION__?.freeze === true ||
    w.__SUCKERPOT_MAP__?.freeze === true ||
    new URLSearchParams(window.location.search).get("motion") === "off"
  )
}

/** Call once before the first render. */
export function applyMotionMode(): void {
  if (motionFrozen()) document.documentElement.dataset.motion = "off"
}
