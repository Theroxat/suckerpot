import { useQuery } from "@tanstack/react-query"
import { feedApi, feedKeys } from "@/lib/network-feed"

/** The state of the community lists on this system. Any signed-in user may read it. */
export function useFeedStatus() {
  return useQuery({
    queryKey: feedKeys.status,
    queryFn: feedApi.status,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
}
