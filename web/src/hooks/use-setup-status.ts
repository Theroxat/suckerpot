import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/app/auth"
import { setupApi, setupKeys } from "@/lib/setup"

/** The setup checklist data. Administrators only: a viewer never asks for it. */
export function useSetupStatus() {
  const { canWrite } = useAuth()
  return useQuery({
    queryKey: setupKeys.status,
    queryFn: setupApi.status,
    enabled: canWrite,
    refetchInterval: 60_000,
  })
}
