import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, FileQuestion, TerminalSquare } from "lucide-react"
import { lazy, Suspense, useMemo } from "react"
import { Link, useParams } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { CountryFlag } from "@/components/country-flag"
import { EmptyState } from "@/components/empty-state"
import { EventTimeline } from "@/components/event-timeline"
import { FindingCard } from "@/components/finding-card"
import { IPChip } from "@/components/ip-chip"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionStory } from "@/components/session-story"
import { SeverityBadge } from "@/components/severity-badge"
import { SkeletonList, SkeletonText } from "@/components/skeletons"
import { TagBadge } from "@/components/tag-badge"
import { replayFromEvents, type ReplaySource } from "@/components/replay/frames"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, api, queryKeys, type SensorEvent, type Session } from "@/lib/api"
import { formatAbsolute, formatDuration, formatNumber, plural } from "@/lib/format"
import { sessionSeverity } from "@/lib/severity"
import { cn } from "@/lib/utils"

// xterm.js is heavy and only this page needs it: load it on demand.
const TerminalReplay = lazy(() =>
  import("@/components/replay/terminal-replay").then((m) => ({ default: m.TerminalReplay })),
)

/** The API pages events 200 at a time; the replay needs the last one (disconnect), so read them all. */
const EVENT_PAGE = 200
const MAX_EVENT_PAGES = 50

async function fetchAllEvents(sessionId: string): Promise<SensorEvent[]> {
  const items: SensorEvent[] = []
  let cursor: string | null = null
  for (let page = 0; page < MAX_EVENT_PAGES; page++) {
    const res = await api.sessionEvents(sessionId, cursor, EVENT_PAGE)
    items.push(...res.items)
    if (!res.next_cursor) break
    cursor = res.next_cursor
  }
  return items
}

const REPLAY_SENSORS = new Set(["ssh", "telnet"])

function replayFinding(source: ReplaySource, commands: number): string {
  const seconds = source.frames.reduce((n, f) => n + f[0], 0)
  const span = formatDuration(seconds)
  if (source.reconstructed) {
    return `${plural(commands, "command")} rebuilt from the session log, about ${span} of activity.`
  }
  return commands
    ? `${plural(commands, "command")} typed over ${span}, replayed here at real speed.`
    : `${span} of terminal output, replayed here at real speed.`
}

function durationOf(s: Session): string {
  const end = s.ended_at ?? s.last_event_at
  return formatDuration((Date.parse(end) - Date.parse(s.started_at)) / 1000)
}

function timelineFinding(s: Session): string {
  const parts: string[] = []
  if (s.login_attempts) parts.push(plural(s.login_attempts, "login attempt"))
  if (s.commands) parts.push(plural(s.commands, "command"))
  if (s.downloads) parts.push(plural(s.downloads, "download attempt"))
  if (s.http_requests) parts.push(plural(s.http_requests, "HTTP request"))
  const what = parts.length ? parts.join(", ") : plural(s.event_count, "event")
  return `${what} in ${durationOf(s)}.`
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 space-y-1">
      <dt className="text-xs text-fg-muted">{label}</dt>
      <dd className="text-sm font-medium break-words text-fg">{children}</dd>
    </div>
  )
}

export function SessionDetailPage() {
  const { sessionId = "" } = useParams()
  const session = useQuery({
    queryKey: queryKeys.session(sessionId),
    queryFn: () => api.session(sessionId),
    retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  })
  const events = useQuery({
    queryKey: queryKeys.sessionEvents(sessionId),
    queryFn: () => fetchAllEvents(sessionId),
    enabled: session.isSuccess,
  })
  const { masked } = useIpMask()
  const eventList = events.data
  const replay = useMemo(() => (eventList ? replayFromEvents(eventList) : null), [eventList])
  const commandCount = eventList?.filter((e) => e.type === "command").length ?? 0

  const back = (
    <Link
      to="/attacks"
      className="inline-flex items-center gap-1.5 text-xs text-fg-muted transition-colors hover:text-fg"
    >
      <ArrowLeft aria-hidden className="size-3.5" /> Attacks
    </Link>
  )

  if (session.isError) {
    const notFound = session.error instanceof ApiError && session.error.status === 404
    return (
      <>
        <div className="pb-6">{back}</div>
        <EmptyState
          icon={FileQuestion}
          title={notFound ? "Session not found" : "Could not load this session"}
          description={
            notFound ? "It may have been removed by the retention job." : session.error.message
          }
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/attacks">Back to attacks</Link>
            </Button>
          }
        />
      </>
    )
  }

  const s = session.data
  const clientTool =
    s?.sensor === "rdp" && s.client_tool && s.client_tool !== "unknown" ? s.client_tool : null
  return (
    <>
      <header className="space-y-4 pb-6">
        {back}
        {s ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <SensorBadge sensor={s.sensor} />
              <SeverityBadge severity={sessionSeverity(s)} />
              {s.tags.map((t) => (
                <TagBadge key={t} tag={t} />
              ))}
            </div>
            <h1 className="text-lg font-medium text-pretty sm:text-xl">
              <span className="sr-only">Session {s.session_id}: </span>
              <SessionStory session={s} layout="block" />
            </h1>
          </>
        ) : (
          <SkeletonText lines={2} className="max-w-xl" />
        )}
      </header>

      {s ? (
        <dl
          className={cn(
            "mb-6 grid grid-cols-2 gap-x-6 gap-y-4 rounded-lg border bg-surface p-4 shadow-sm sm:grid-cols-3 sm:p-5",
            // Six cells: "Started" (a full date and time zone) gets more room so it stays on one line.
            clientTool
              ? "lg:grid-cols-[minmax(0,1.5fr)_repeat(5,minmax(0,1fr))]"
              : "lg:grid-cols-5",
          )}
        >
          <Meta label="Started">{formatAbsolute(s.started_at)}</Meta>
          <Meta label="Duration">{s.ended_at ? durationOf(s) : "Still connected"}</Meta>
          <Meta label="Events">{formatNumber(s.event_count)}</Meta>
          {clientTool ? <Meta label="Client">{clientTool}</Meta> : null}
          <Meta label="Ports">
            <span className="font-mono text-xs">
              {s.src_port} → {s.dst_port}
            </span>
          </Meta>
          <Meta label="Session ID">
            <span className="font-mono text-xs">{s.session_id}</span>
          </Meta>
        </dl>
      ) : null}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {s && REPLAY_SENSORS.has(s.sensor) ? (
            <FindingCard
              eyebrow="Terminal replay"
              finding={
                events.isPending
                  ? "Loading the recording…"
                  : replay
                    ? replayFinding(replay, commandCount)
                    : "No commands were run, so there is nothing to replay."
              }
            >
              {events.isPending ? (
                <Skeleton className="h-64 w-full sm:h-80" />
              ) : events.isError ? (
                <p className="text-sm text-fg-muted">Could not load the recording.</p>
              ) : replay ? (
                <Suspense fallback={<Skeleton className="h-64 w-full sm:h-80" />}>
                  <TerminalReplay source={replay} masked={masked} />
                </Suspense>
              ) : (
                <EmptyState
                  variant="bare"
                  icon={TerminalSquare}
                  title="Nothing was typed"
                  description="The client connected but never ran a command."
                  className="py-8"
                />
              )}
            </FindingCard>
          ) : null}

          <FindingCard
            eyebrow="Timeline"
            finding={s ? timelineFinding(s) : "Loading the timeline…"}
            bodyClassName="px-0 sm:px-0 pt-3 pb-2 sm:pb-2"
          >
            {events.isPending ? (
              <SkeletonList rows={6} />
            ) : events.isError ? (
              <p className="px-5 py-6 text-sm text-fg-muted">Could not load events.</p>
            ) : (
              <EventTimeline events={events.data} />
            )}
          </FindingCard>
        </div>

        <FindingCard
          eyebrow="Source"
          finding={
            s ? (
              <span className="inline-flex flex-wrap items-center gap-2">
                <IPChip ip={s.src_ip} />
                {s.country ? <CountryFlag code={s.country} showName /> : null}
              </span>
            ) : (
              "…"
            )
          }
          detail={s?.org ? `${s.org}${s.asn ? ` · AS${s.asn}` : ""}` : "Not enriched yet"}
          className="self-start"
        >
          <dl className="grid grid-cols-2 gap-4">
            <Meta label="Abuse score">
              {s?.abuse_score != null ? `${s.abuse_score} / 100` : "–"}
            </Meta>
            <Meta label="Known scanner">
              {s?.known_scanner == null ? "–" : s.known_scanner ? "Yes" : "No"}
            </Meta>
          </dl>
          {s ? (
            <div className="mt-4 flex flex-col gap-2">
              <Button asChild variant="outline" size="sm" className="w-full">
                <Link to={`/attackers/${encodeURIComponent(s.src_ip)}`}>Attacker profile</Link>
              </Button>
              <Button asChild variant="ghost" size="sm" className="w-full">
                <Link to={`/attacks?src_ip=${encodeURIComponent(s.src_ip)}`}>
                  All sessions from this address
                </Link>
              </Button>
            </div>
          ) : null}
        </FindingCard>
      </div>
    </>
  )
}
