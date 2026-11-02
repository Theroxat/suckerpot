import { useId } from "react"
import { Trash2 } from "lucide-react"
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
      description="Nothing more is sent from this moment, and your data is deleted on both sides. You can join again later."
      hint="Leaving asks for your own dashboard password again."
      confirmLabel="Leave the network"
      pendingLabel="Leaving…"
      run={async (password) => {
        await networkApi.leave(password)
      }}
      onDone={() => void refresh()}
    >
      <div className="grid gap-3 text-sm sm:grid-cols-2">
        <DeletedList
          title="Deleted on this system"
          items={[
            "The node key",
            "Your pseudonym",
            "The list of sent batches",
            "The network figures",
          ]}
        />
        <DeletedList
          title="Deleted at the hub"
          items={["Your node", "What it sent", "Your takedown checks", "Your member entry"]}
        />
      </div>
      <p className="text-xs text-fg-muted">
        If the hub cannot be reached now, Selfhostr keeps trying for 7 days.
      </p>
    </AdminActionDialog>
  )
}

function DeletedList({ title, items }: { title: string; items: readonly string[] }) {
  const id = useId()
  return (
    <div className="rounded-md border p-3">
      <p id={id} className="mb-1.5 text-xs font-medium text-fg">
        {title}
      </p>
      <ul aria-labelledby={id} className="space-y-1 text-xs text-fg-muted">
        {items.map((i) => (
          <li key={i} className="flex items-start gap-2">
            <Trash2 aria-hidden className="mt-0.5 size-3 shrink-0 text-fg-subtle" />
            {i}
          </li>
        ))}
      </ul>
    </div>
  )
}
