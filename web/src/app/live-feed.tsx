import { useEffect, useState } from "react"
import { LiveClient, type LiveClientOptions } from "@/lib/live-client"
import { useAuth } from "./auth"
import { LiveFeedContext } from "./use-live-feed"

/** Owns the single live connection of the tab. Mount once, at the app root. */
export function LiveFeedProvider({
  children,
  options,
}: {
  children: React.ReactNode
  options?: LiveClientOptions
}) {
  const [client] = useState(() => new LiveClient(options))
  // The server refuses the socket without a session: connect only once signed in.
  const { status } = useAuth()
  const signedIn = status === "authenticated"
  useEffect(() => {
    if (!signedIn) return
    client.start()
    return () => client.stop()
  }, [client, signedIn])
  return <LiveFeedContext value={client}>{children}</LiveFeedContext>
}
