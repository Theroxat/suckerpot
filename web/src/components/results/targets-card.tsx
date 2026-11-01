import { useInfiniteQuery } from "@tanstack/react-query"
import { useMemo } from "react"
import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { SegmentedControl } from "@/components/segmented-control"
import { TagBadge } from "@/components/tag-badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useUrlParam } from "@/hooks/use-url-param"
import { formatNumber } from "@/lib/format"
import {
  CHANNEL_LABEL,
  resultKeys,
  resultsApi,
  ROLE_LABEL,
  type ResultFilters,
  type TargetRole,
  type TargetState,
} from "@/lib/results"
import { defang, shortDelay } from "@/lib/results-sentences"
import { TargetStateBadge } from "./badges"

type RoleFilter = "all" | TargetRole
type StateFilter = "all" | TargetState

const ROLE_OPTIONS = [
  { value: "all", label: "All" },
  { value: "payload_url", label: "URLs" },
  { value: "payload_host", label: "Hosts" },
  { value: "attack_source", label: "Addresses" },
  { value: "c2", label: "C2" },
] as const satisfies readonly { value: RoleFilter; label: string }[]

const STATE_OPTIONS = [
  { value: "all", label: "Any state" },
  { value: "up", label: "Up" },
  { value: "down", label: "Down" },
  { value: "changed", label: "Changed" },
] as const satisfies readonly { value: StateFilter; label: string }[]

const isRole = (v: string | null): v is TargetRole => v !== null && v in ROLE_LABEL
const isState = (v: string | null): v is TargetState =>
  v === "up" || v === "down" || v === "changed" || v === "unknown"

/** The tracked targets, newest report first. Values are defanged text; a row opens the target. */
export function TargetsCard({ filters }: { filters: ResultFilters }) {
  const [roleParam, setRole] = useUrlParam("role")
  const [stateParam, setState] = useUrlParam("state")
  const role: RoleFilter = isRole(roleParam) ? roleParam : "all"
  const state: StateFilter = isState(stateParam) ? stateParam : "all"
  const f = {
    ...filters,
    role: role === "all" ? undefined : role,
    state: state === "all" ? undefined : state,
  }
  const q = useInfiniteQuery({
    queryKey: resultKeys.targets(f),
    queryFn: ({ pageParam }) => resultsApi.targets(f, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const items = useMemo(() => (q.data?.pages ?? []).flatMap((p) => p.items), [q.data])
  const down = items.filter((t) => t.state === "down").length
  const finding = q.isPending
    ? "Listing the targets…"
    : items.length === 0
      ? "No tracked target matches these filters."
      : `${formatNumber(items.length)} ${items.length === 1 ? "target" : "targets"} listed; ${formatNumber(down)} ${down === 1 ? "is" : "are"} down.`
  return (
    <FindingCard
      eyebrow="Targets"
      finding={finding}
      detail="Addresses are shown defanged and are never links. A row opens its timeline."
      action={
        <div className="flex flex-wrap gap-2">
          <SegmentedControl
            label="Target type"
            value={role}
            onChange={(v) => setRole(v === "all" ? null : v)}
            options={ROLE_OPTIONS}
            className="max-w-full overflow-x-auto"
          />
          <SegmentedControl
            label="Target state"
            value={state}
            onChange={(v) => setState(v === "all" ? null : v)}
            options={STATE_OPTIONS}
            className="max-w-full overflow-x-auto"
          />
        </div>
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
      className="normal-nums"
    >
      {q.isPending ? (
        <div className="px-4 pb-5 sm:px-5">
          <Skeleton className="h-40 w-full" />
        </div>
      ) : q.isError ? (
        <p role="alert" className="border-t px-4 py-6 text-sm text-fg-muted sm:px-5">
          The targets could not be loaded.
        </p>
      ) : items.length === 0 ? null : (
        <div className="relative overflow-x-auto border-t">
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Tracked targets</caption>
            <thead className="text-xs text-fg-muted">
              <tr className="border-b">
                <th scope="col" className="px-4 py-2 font-medium sm:px-5">
                  Target
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  Provider
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  Reported
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  Channel
                </th>
                <th scope="col" className="px-2 py-2 font-medium">
                  State
                </th>
                <th scope="col" className="px-4 py-2 text-right font-medium sm:px-5">
                  Time to takedown
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {items.map((t) => (
                <tr key={t.id} className="hover:bg-surface-hover/50">
                  <td className="max-w-[22rem] px-4 py-2 sm:px-5">
                    <Link
                      to={`/defend/results/targets/${t.id}`}
                      className={
                        "block truncate font-mono text-xs text-fg underline-offset-4 hover:underline" +
                        (t.parent_id ? " pl-3" : "")
                      }
                      title={defang(t.value)}
                    >
                      {defang(t.value)}
                    </Link>
                    <span className="text-2xs text-fg-subtle">{ROLE_LABEL[t.role]}</span>
                  </td>
                  <td className="px-2 py-2 whitespace-nowrap">
                    <span className="inline-flex items-center gap-2 text-fg-muted">
                      {t.country ? <CountryFlag code={t.country} /> : null}
                      {t.asn ? (
                        <Link
                          to={`/attackers?asn=${t.asn}`}
                          className="font-mono text-xs hover:text-fg"
                        >
                          AS{t.asn}
                        </Link>
                      ) : (
                        (t.provider_name ?? "unknown")
                      )}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    <RelativeTime iso={t.reported_at} />
                  </td>
                  <td className="px-2 py-2">
                    <span className="flex flex-wrap gap-1">
                      {t.channels.map((c) => (
                        <TagBadge key={c} tag={CHANNEL_LABEL[c]} href={null} />
                      ))}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    <TargetStateBadge state={t.state} role={t.role} />
                  </td>
                  <td className="px-4 py-2 text-right whitespace-nowrap sm:px-5">
                    {t.ttd_s == null ? (
                      <span className="text-fg-subtle">none yet</span>
                    ) : (
                      `within ${shortDelay(t.ttd_s)}`
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.hasNextPage ? (
        <div className="border-t px-4 py-3 sm:px-5">
          <Button
            variant="outline"
            size="sm"
            disabled={q.isFetchingNextPage}
            onClick={() => void q.fetchNextPage()}
          >
            {q.isFetchingNextPage ? "Loading…" : "Show more"}
          </Button>
        </div>
      ) : null}
    </FindingCard>
  )
}
