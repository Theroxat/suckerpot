import type { LiveStatus } from "@/components/live-indicator"
import { useLiveFeed } from "./use-live-feed"

/** Connection status for the shell, straight from the shared live feed. */
export function useLiveStatus(): { status: LiveStatus; detail: string | undefined } {
  const { status, transport } = useLiveFeed()
  return {
    status,
    detail: status === "live" && transport === "polling" ? "Polling" : undefined,
  }
}
