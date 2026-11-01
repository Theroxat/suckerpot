import { networkApi } from "@/lib/network"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { useRefreshNetwork } from "./use-network"

/** Leaving is one click plus the password. The text says what is deleted, and where. */
export function LeaveDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const refresh = useRefreshNetwork()
  return (
    <AdminActionDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Leave the Selfhostr network?"
      description={
        <>
          Nothing more is sent from this moment. On this system, the node key, your pseudonym, the
          list of sent batches and the network figures are deleted. At the hub, your node, what it
          sent, your takedown checks and your member entry are deleted. If the hub cannot be reached
          now, Selfhostr keeps trying for 7 days. You can join again later.
        </>
      }
      hint="Leaving asks for your own dashboard password again."
      confirmLabel="Leave the network"
      pendingLabel="Leaving…"
      run={async (password) => {
        await networkApi.leave(password)
      }}
      onDone={() => void refresh()}
    />
  )
}
