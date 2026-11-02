import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/app/auth"
import { wizardApi, wizardKeys } from "@/lib/setup-wizard"

/** Progress for administrators only; a viewer never asks. */
export function useWizardProgress() {
  const { canWrite } = useAuth()
  return useQuery({
    queryKey: wizardKeys.progress,
    queryFn: wizardApi.progress,
    enabled: canWrite,
    staleTime: 30_000,
    retry: false,
  })
}
