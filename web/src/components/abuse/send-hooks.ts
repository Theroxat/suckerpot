import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/app/auth"
import { queueRefetch, sendApi, sendKeys, type SendMode } from "@/lib/abuse-send"

/** The send queue, polled while something is on its way. Administrators only. */
export function useSendQueue() {
  const { canWrite } = useAuth()
  return useQuery({
    queryKey: sendKeys.queue,
    queryFn: sendApi.queue,
    enabled: canWrite,
    refetchInterval: (q) => queueRefetch(q.state.data?.items),
  })
}

/** The sending mode, or "off" until it is known. */
export function useSendMode(): SendMode {
  const { canWrite } = useAuth()
  const q = useQuery({ queryKey: sendKeys.smtp, queryFn: sendApi.smtp, enabled: canWrite })
  return q.data?.configured ? q.data.mode : "off"
}
