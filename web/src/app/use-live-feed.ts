import { createContext, use, useSyncExternalStore } from "react"
import type { LiveClient, LiveFeedState } from "@/lib/live-client"

export const LiveFeedContext = createContext<LiveClient | null>(null)

/** Status, events (newest first), stats and transport of the shared live feed. */
export function useLiveFeed(): LiveFeedState {
  const client = use(LiveFeedContext)
  if (!client) throw new Error("useLiveFeed needs <LiveFeedProvider>")
  return useSyncExternalStore(client.subscribe, client.getSnapshot, client.getSnapshot)
}
