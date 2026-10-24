import {
  CircleCheck,
  Download,
  Globe,
  KeyRound,
  LogOut,
  Plug,
  Radar,
  SquareChevronRight,
  type LucideIcon,
} from "lucide-react"
import { IPChip } from "@/components/ip-chip"
import { RelativeTime } from "@/components/relative-time"
import type { SensorEvent } from "@/lib/api"
import { useIpMask } from "@/app/ip-mask"
import { formatClock, formatDuration, maskIpsInText } from "@/lib/format"
import { isSevereEvent } from "@/lib/severity"
import { sensorMeta } from "@/lib/sensors"
import { cn } from "@/lib/utils"

interface EventView {
  icon: LucideIcon
  label: string
  summary: React.ReactNode
  severe?: boolean
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.length ? v : null
}

/** Attacker-supplied text: monospaced, and masked in screenshot mode. */
function Mono({ children }: { children: string | null }) {
  const { masked } = useIpMask()
  return (
    <code className="truncate font-mono text-xs text-fg">
      {masked && children ? maskIpsInText(children) : children}
    </code>
  )
}

/** What an event says, in words. Unknown types fall back gracefully. */
function viewEvent(e: SensorEvent): EventView {
  const d = e.data
  switch (e.type) {
    case "connect":
      return {
        icon: Plug,
        label: "Connect",
        summary: (
          <>
            Connected to port {e.dst_port}
            {str(d.client_version) ? (
              <span className="text-fg-muted">
                {" "}
                with <Mono>{str(d.client_version)}</Mono>
              </span>
            ) : null}
          </>
        ),
      }
    case "login_attempt": {
      const ok = d.success === true
      return {
        icon: ok ? CircleCheck : KeyRound,
        label: ok ? "Login succeeded" : "Login attempt",
        summary: (
          <span className="inline-flex min-w-0 items-center gap-2">
            <span className="shrink-0 text-fg-muted">{ok ? "Logged in as" : "Tried"}</span>
            <Mono>{str(d.username) ?? "?"}</Mono>
            <span className="shrink-0 text-fg-subtle">/</span>
            <Mono>{str(d.password) ?? "(no password)"}</Mono>
          </span>
        ),
      }
    }
    case "command":
      return {
        icon: SquareChevronRight,
        label: "Command",
        summary: (
          <span className="inline-flex min-w-0 items-center gap-2">
            <span aria-hidden className="shrink-0 font-mono text-xs text-fg-subtle">
              $
            </span>
            <Mono>{str(d.input) ?? ""}</Mono>
          </span>
        ),
      }
    case "download_attempt":
      return {
        icon: Download,
        label: "Download attempt",
        severe: true,
        summary: (
          <span className="inline-flex min-w-0 items-center gap-2">
            <span className="shrink-0 text-fg-muted">
              {str(d.tool) ? `${str(d.tool)} fetch` : "Download"}
            </span>
            <Mono>{str(d.url) ?? "unknown URL"}</Mono>
          </span>
        ),
      }
    case "http_request":
      return {
        icon: Globe,
        label: "HTTP request",
        summary: (
          <span className="inline-flex min-w-0 items-center gap-2">
            <span className="shrink-0 font-mono text-xs font-medium text-fg-muted">
              {str(d.method) ?? "GET"}
            </span>
            <Mono>{str(d.path) ?? "/"}</Mono>
            {typeof d.status === "number" ? (
              <span className="shrink-0 font-mono text-xs text-fg-subtle">{d.status}</span>
            ) : null}
          </span>
        ),
      }
    case "disconnect":
      return {
        icon: LogOut,
        label: "Disconnect",
        summary: (
          <span className="text-fg-muted">
            Disconnected
            {typeof d.duration_s === "number" ? ` after ${formatDuration(d.duration_s)}` : ""}
          </span>
        ),
      }
    case "scan":
      return { icon: Radar, label: "Probe", summary: <span className="text-fg-muted">Probe</span> }
    default:
      return {
        icon: Radar,
        label: e.type,
        summary: <span className="text-fg-muted">{e.type}</span>,
      }
  }
}

interface EventRowProps {
  event: SensorEvent
  /** Show the sensor label (feeds mixing sensors). */
  showSensor?: boolean
  showIp?: boolean
  /** `clock` for timelines (18:02:11), `relative` for live feeds (5 min ago). */
  time?: "clock" | "relative"
  /** Slides in once (new item in a live feed). */
  isNew?: boolean
  /** Sensor colour bar on the left edge (feeds that mix sensors). */
  accent?: boolean
  className?: string
}

export function EventRow({
  event,
  showSensor = false,
  showIp = false,
  time = "clock",
  isNew = false,
  accent = false,
  className,
}: EventRowProps) {
  const meta = sensorMeta(event.sensor)
  const view = viewEvent(event)
  const Icon = view.icon

  return (
    <div
      className={cn(
        "group/event relative flex min-h-11 items-center gap-3 px-4 py-2 text-sm sm:px-5",
        isNew && "animate-slide-in",
        className,
      )}
    >
      {/* Sensor accent: colour plus the label/icon in the row, never colour alone. */}
      {accent ? (
        <span
          aria-hidden
          className={cn(
            "absolute inset-y-2 left-0 w-0.5 rounded-full",
            meta?.fill ?? "bg-fg-subtle",
          )}
        />
      ) : null}
      {time === "clock" ? (
        <time
          dateTime={event.ts}
          className="w-16 shrink-0 font-mono text-xs text-fg-subtle"
          title={new Date(event.ts).toString()}
        >
          {formatClock(event.ts)}
        </time>
      ) : null}
      <span
        className={cn(
          "flex size-7 shrink-0 items-center justify-center rounded-md border",
          view.severe || isSevereEvent(event.type, event.tags)
            ? "tint-severe border-sev-severe/30 text-sev-severe"
            : "text-fg-muted",
        )}
        title={view.label}
      >
        <Icon aria-hidden className="size-3.5" strokeWidth={2} />
        <span className="sr-only">{view.label}</span>
      </span>
      <div className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden whitespace-nowrap">
        {view.summary}
      </div>
      {showIp ? <IPChip ip={event.src_ip} className="hidden shrink-0 sm:inline-flex" /> : null}
      {showSensor && meta ? (
        <span className={cn("inline-flex shrink-0 items-center gap-1 text-xs", meta.text)}>
          <meta.icon aria-hidden className="size-3.5" />
          <span className="hidden sm:inline">{meta.label}</span>
          <span className="sr-only sm:hidden">{meta.label}</span>
        </span>
      ) : null}
      {time === "relative" ? <RelativeTime iso={event.ts} className="shrink-0 text-xs" /> : null}
    </div>
  )
}
