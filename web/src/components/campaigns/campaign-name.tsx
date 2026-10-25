import { useQuery } from "@tanstack/react-query"
import { api, queryKeys } from "@/lib/api"

/** The name of a campaign for a filter chip; "#id" until it loads or if it cannot be read. */
export function CampaignName({ id }: { id: string }) {
  const n = /^\d{1,15}$/.test(id) ? Number(id) : null
  const q = useQuery({
    queryKey: queryKeys.campaign(n ?? 0),
    queryFn: () => api.campaign(n ?? 0),
    enabled: n !== null,
    staleTime: 60_000,
  })
  return <span className="max-w-64 truncate">{q.data?.name ?? `#${id}`}</span>
}
