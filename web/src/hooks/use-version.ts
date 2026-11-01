import { useQuery } from "@tanstack/react-query"
import { versionApi, versionKeys } from "@/lib/version"

/** The running version and the update check. Any signed-in user may read it. */
export function useVersion() {
  return useQuery({
    queryKey: versionKeys.current,
    queryFn: versionApi.get,
    staleTime: 10 * 60_000,
    retry: false,
  })
}
