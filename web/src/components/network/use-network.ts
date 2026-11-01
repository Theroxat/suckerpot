import { useQuery, useQueryClient } from "@tanstack/react-query"
import { networkApi, networkKeys, type NetworkStatus } from "@/lib/network"

/** While the worker joins or leaves in the background, look again every few seconds. */
function statusInterval(s: NetworkStatus | undefined): number | false {
  return s && (s.state === "enrolling" || s.state === "leaving") ? 3_000 : 60_000
}

/** The status of this system in the network. Any signed-in user may read it. */
export function useNetworkStatus() {
  return useQuery({
    queryKey: networkKeys.status,
    queryFn: networkApi.status,
    refetchInterval: (query) => statusInterval(query.state.data),
  })
}

/** After a change, everything the network pages show is stale. */
export function useRefreshNetwork() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ["network"] })
}
