import { vi } from "vitest"

/** jsdom has no ResizeObserver (popovers and dialogs position themselves with it). */
export function stubResizeObserver(): void {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe = () => undefined
      unobserve = () => undefined
      disconnect = () => undefined
    },
  )
}
