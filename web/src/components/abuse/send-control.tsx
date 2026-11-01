import { useQueryClient } from "@tanstack/react-query"
import { Send } from "lucide-react"
import { useEffect, useRef, useState, type ReactNode } from "react"
import { useAuth } from "@/app/auth"
import { useSendMode } from "@/components/abuse/send-hooks"
import { ConfirmDialog } from "@/components/abuse/status-dialogs"
import { Button } from "@/components/ui/button"
import { abuseKeys } from "@/lib/abuse"
import { describeRequest, describeSendError, sendApi, type QueueItem } from "@/lib/abuse-send"
import { formatClock } from "@/lib/format"

interface SendControlProps {
  /** The queue entry of the report; undefined when it is not ready to send. */
  item: QueueItem | undefined
  reportId: string
  recipient: string
  /** Buttons that sit in the same row as Send now (the queue passes its own). */
  actions?: ReactNode
}

/**
 * What SuckerPot's own sending adds to a report: "Send now" in click mode, "Sending at hh:mm" with
 * Cancel in automatic mode, and the state of the last request in plain words.
 */
export function SendControl({ item, reportId, recipient, actions }: SendControlProps) {
  const { canWrite } = useAuth()
  const mode = useSendMode()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [cancelError, setCancelError] = useState<string | null>(null)
  const status = item?.last_request?.status
  const was = useRef(status)

  // A request that finished (the report left the queue) changes the report itself: reload it.
  useEffect(() => {
    if (was.current === "pending" && status !== "pending") {
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
    }
    was.current = status
  }, [status, qc])

  if (!canWrite) return null
  const pending = status === "pending"
  const sentence = describeRequest(item?.last_request ?? null)
  const at = mode === "auto" && !pending ? item?.scheduled_at : null
  const canSend = mode === "click" && item !== undefined && !pending

  if (!sentence && !at && !canSend && !actions) return null

  async function cancel() {
    setCancelError(null)
    try {
      await sendApi.cancel(reportId)
      await qc.invalidateQueries({ queryKey: abuseKeys.all })
    } catch (e) {
      setCancelError(describeSendError(e))
    }
  }

  return (
    <div className="space-y-2">
      {canSend || actions ? (
        <div className="flex flex-wrap items-center gap-2">
          {canSend ? (
            <Button size="sm" onClick={() => setOpen(true)}>
              <Send aria-hidden /> Send now
            </Button>
          ) : null}
          {actions}
        </div>
      ) : null}
      {at ? (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-fg-muted">
          <span>
            Sending at <span className="tabular-nums">{formatClock(at)}</span>
          </span>
          <span aria-hidden>·</span>
          <Button size="xs" variant="outline" onClick={() => void cancel()}>
            Cancel
          </Button>
        </p>
      ) : null}
      {sentence ? (
        <p
          role="status"
          className={status === "failed" ? "text-sm text-fg" : "text-sm text-fg-muted"}
        >
          {sentence}
        </p>
      ) : null}
      <p role="alert" className="text-sm text-fg empty:hidden">
        {cancelError}
      </p>
      <ConfirmDialog
        open={open}
        onOpenChange={setOpen}
        title="Send this report now?"
        description={`The message goes to ${recipient} from your SMTP account, through the VPN. It cannot be recalled once sent.`}
        confirmLabel="Send now"
        describe={describeSendError}
        run={async () => {
          await sendApi.send(reportId)
          await qc.invalidateQueries({ queryKey: abuseKeys.all })
        }}
      />
    </div>
  )
}
