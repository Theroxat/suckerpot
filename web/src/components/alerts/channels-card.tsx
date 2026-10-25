import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  CircleAlert,
  CircleCheck,
  Ellipsis,
  Hash,
  KeyRound,
  Mail,
  Plus,
  Send,
  Trash2,
  Users,
  type LucideIcon,
} from "lucide-react"
import { useState } from "react"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Switch } from "@/components/ui/switch"
import {
  alertKeys,
  alertsApi,
  channelsFinding,
  deleteChannel,
  describeTest,
  KIND_LABEL,
  requestChannelTest,
  testInFlight,
  updateChannel,
  type AlertChannel,
  type ChannelKind,
} from "@/lib/alerts"
import { cn } from "@/lib/utils"
import { AddChannelDialog, ChangeTargetDialog } from "./channel-dialogs"

const KIND_ICON: Record<ChannelKind, LucideIcon> = { discord: Hash, teams: Users, email: Mail }

function TestLine({ channel }: { channel: AlertChannel }) {
  const text = describeTest(channel.last_test)
  if (!text) return null
  const failed = channel.last_test?.state === "failed" || channel.last_test?.state === "refused"
  const Icon = failed ? CircleAlert : CircleCheck
  return (
    <p
      className={cn(
        "flex items-start gap-1.5 text-xs",
        failed ? "text-sev-warning" : "text-fg-muted",
      )}
      role="status"
    >
      <Icon aria-hidden className="mt-0.5 size-3 shrink-0" />
      {text}
    </p>
  )
}

function ChannelRow({
  channel,
  writable,
  alertsOn,
  onChanged,
  onError,
}: {
  channel: AlertChannel
  writable: boolean
  alertsOn: boolean
  onChanged: () => void
  onError: (message: string) => void
}) {
  const [busy, setBusy] = useState(false)
  const [changing, setChanging] = useState(false)
  const [removing, setRemoving] = useState(false)
  const Icon = KIND_ICON[channel.kind]
  const queued = channel.last_test?.state === "queued"

  async function act(fn: () => Promise<unknown>) {
    if (busy) return
    setBusy(true)
    try {
      await fn()
      onChanged()
    } catch (e) {
      onError(e instanceof Error ? e.message : "The change could not be saved.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="grid grid-cols-[auto_1fr_auto] items-start gap-x-3 gap-y-2 px-4 py-3.5 sm:px-5">
      <span className="mt-0.5 flex size-8 items-center justify-center rounded-md border bg-bg text-fg-muted">
        <Icon aria-hidden className="size-4" strokeWidth={1.75} />
      </span>
      <div className="min-w-0 space-y-1">
        <p className="flex flex-wrap items-baseline gap-x-2 text-sm font-medium text-fg">
          <span className="truncate">{channel.name}</span>
          <span className="text-xs font-normal text-fg-muted">
            {KIND_LABEL[channel.kind]} · {channel.target_hint}
          </span>
        </p>
        <p className="text-xs text-fg-muted">
          {channel.mask_ips
            ? "Attacker IP addresses are partly hidden in messages."
            : "Attacker IP addresses are shown in messages (made harmless, not clickable)."}
        </p>
        <TestLine channel={channel} />
      </div>
      <div className="flex items-center gap-2">
        <Switch
          size="sm"
          checked={channel.enabled}
          disabled={!writable || busy}
          onCheckedChange={(enabled) => void act(() => updateChannel(channel.id, { enabled }))}
          aria-label={`${channel.name} is ${channel.enabled ? "on" : "off"}`}
        />
        {writable ? (
          <>
            <Button
              variant="outline"
              size="sm"
              disabled={busy || queued || !alertsOn}
              title={alertsOn ? undefined : "Alerts are switched off on this server"}
              onClick={() => void act(() => requestChannelTest(channel.id))}
            >
              <Send aria-hidden />
              {queued ? "Sending…" : "Send test"}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${channel.name}`}>
                  <Ellipsis aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem
                  onSelect={() =>
                    void act(() => updateChannel(channel.id, { mask_ips: !channel.mask_ips }))
                  }
                >
                  {channel.mask_ips ? "Show full IP addresses" : "Hide the end of IP addresses"}
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setChanging(true)}>
                  <KeyRound aria-hidden />
                  Change address…
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onSelect={() => setRemoving(true)}>
                  <Trash2 aria-hidden />
                  Delete…
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        ) : null}
      </div>
      <ChangeTargetDialog
        channel={channel}
        open={changing}
        onOpenChange={setChanging}
        onDone={onChanged}
      />
      <Dialog open={removing} onOpenChange={setRemoving}>
        <DialogContent className="bg-popover">
          <DialogHeader className="text-left">
            <DialogTitle>Delete “{channel.name}”?</DialogTitle>
            <DialogDescription>
              Alerts stop going there and the stored address is erased. Rules that only used this
              channel are switched off.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRemoving(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() =>
                void act(async () => {
                  await deleteChannel(channel.id)
                  setRemoving(false)
                })
              }
            >
              Delete channel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </li>
  )
}

/** Where alerts go. Administrators add, test, edit and remove; everyone else can look. */
export function ChannelsCard() {
  const { canWrite } = useAuth()
  const client = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const status = useQuery({ queryKey: alertKeys.status, queryFn: alertsApi.status })
  const channels = useQuery({
    queryKey: alertKeys.channels,
    queryFn: alertsApi.channels,
    // While a test message is on its way through ingest, look again every few seconds.
    refetchInterval: (query) => (testInFlight(query.state.data) ? 3_000 : false),
  })
  const list = channels.data
  const editing = status.data?.editing_enabled ?? true

  function changed() {
    setError(null)
    void client.invalidateQueries({ queryKey: alertKeys.channels })
    void client.invalidateQueries({ queryKey: alertKeys.rules })
    void client.invalidateQueries({ queryKey: alertKeys.status })
  }

  return (
    <FindingCard
      eyebrow="Alert channels"
      finding={list ? channelsFinding(status.data, list) : "Checking the alert channels…"}
      detail={
        status.data && !status.data.alerts.smtp_configured
          ? "E-mail needs SMTP settings in .env before it can send. Discord and Teams work without."
          : "Messages are sent by the server, never by your browser. At most 10 a minute and 100 a day per channel."
      }
      action={
        canWrite && editing ? (
          <AddChannelDialog
            onDone={changed}
            trigger={
              <Button size="sm">
                <Plus aria-hidden />
                Add channel
              </Button>
            }
          />
        ) : null
      }
      bodyClassName="px-0 sm:px-0 pt-3 pb-1 sm:pb-1"
    >
      {channels.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={3} className="py-1" />
        </div>
      ) : !list ? (
        <p className="px-4 pb-3 text-sm text-fg-muted sm:px-5">
          The channels are not available right now.
        </p>
      ) : (
        <>
          {error ? (
            <p role="alert" className="border-t px-4 py-3 text-sm text-sev-warning sm:px-5">
              {error}
            </p>
          ) : null}
          {!editing && status.data?.editing_reason ? (
            <p className="border-t px-4 py-3 text-sm text-fg-muted sm:px-5">
              {status.data.editing_reason}
            </p>
          ) : null}
          {list.length === 0 ? (
            <p className="border-t px-4 py-6 text-sm text-fg-muted sm:px-5">
              No channel yet.{" "}
              {canWrite ? "Add one to receive alerts." : "An administrator can add one."}
            </p>
          ) : (
            <ul aria-label="Alert channels" className="divide-y border-t">
              {list.map((c) => (
                <ChannelRow
                  key={c.id}
                  channel={c}
                  writable={canWrite && editing}
                  alertsOn={status.data?.alerts.enabled ?? true}
                  onChanged={changed}
                  onError={setError}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </FindingCard>
  )
}
