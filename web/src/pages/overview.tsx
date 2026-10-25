import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { Link } from "react-router"
import { SensorActivityChart } from "@/components/charts/sensor-activity-chart"
import { CountryFlag } from "@/components/country-flag"
import { FindingCard } from "@/components/finding-card"
import { InsightsCard } from "@/components/insights/insights-card"
import { LatestEventsCard } from "@/components/latest-events-card"
import { PageHeader } from "@/components/page-header"
import { StatTile } from "@/components/stat-tile"
import { TopList, type TopListItem } from "@/components/top-list"
import { Button } from "@/components/ui/button"
import { formatHour } from "@/lib/chart-time"
import { api, queryKeys, type TopResponse } from "@/lib/api"
import {
  deltaRatio,
  describeActivity,
  describeCountries,
  describeCredential,
  splitWindows,
  sumBySensor,
} from "@/lib/findings"
import { countryName, formatNumber, formatPercent } from "@/lib/format"
import { SENSORS } from "@/lib/api"

const HOUR = 3_600_000

function useWindow() {
  // Hour-aligned, so the query key is stable between renders.
  const [end] = useState(() => Math.ceil(Date.now() / HOUR) * HOUR)
  return {
    since48: new Date(end - 48 * HOUR).toISOString(),
    since24: new Date(end - 24 * HOUR).toISOString(),
  }
}

function credentialItems(top: TopResponse | undefined, field: "username" | "password") {
  return (top?.items ?? []).map<TopListItem>((i) => ({
    key: i.value,
    name: i.value,
    label: <span className="font-mono text-xs">{i.value}</span>,
    count: i.count,
    share: i.share,
    href: `/trends?${field}=${encodeURIComponent(i.value)}`,
  }))
}

export function OverviewPage() {
  const { since48, since24 } = useWindow()
  const summary = useQuery({ queryKey: queryKeys.summary, queryFn: api.summary })
  const series = useQuery({
    queryKey: queryKeys.timeseries("1h", { since: since48 }),
    queryFn: () => api.timeseries("1h", { since: since48 }),
  })
  const range = { since: since24 }
  const countries = useQuery({
    queryKey: queryKeys.top("country", range),
    queryFn: () => api.top("country", range, 6),
  })
  const usernames = useQuery({
    queryKey: queryKeys.top("username", range),
    queryFn: () => api.top("username", range, 5),
  })
  const passwords = useQuery({
    queryKey: queryKeys.top("password", range),
    queryFn: () => api.top("password", range, 5),
  })

  const s = summary.data
  const points = series.data?.points
  const [prev, cur] = points ? splitWindows(points) : [[], []]
  const sessionsNow = SENSORS.reduce((n, x) => n + sumBySensor(cur, "sessions")[x], 0)
  const sessionsPrev = SENSORS.reduce((n, x) => n + sumBySensor(prev, "sessions")[x], 0)
  const attacksDelta = points ? deltaRatio(sessionsNow, sessionsPrev) : null

  const activity = describeActivity(cur, formatHour)
  const countryFinding = describeCountries(countries.data)

  const countryItems = (countries.data?.items ?? [])
    .filter((i) => i.value)
    .map<TopListItem>((i) => {
      const name = countryName(i.value) ?? i.value
      return {
        key: i.value,
        name,
        label: <CountryFlag code={i.value} showName className="text-fg" />,
        count: i.count,
        share: i.share,
        href: `/attackers?country=${encodeURIComponent(i.value)}`,
      }
    })

  return (
    <>
      <PageHeader
        title="Overview"
        description={
          s
            ? `${formatNumber(s.sessions)} sessions from ${formatNumber(s.unique_ips)} addresses in the last ${s.window_hours} hours.`
            : "The last 24 hours at a glance."
        }
        actions={
          <Button asChild variant="outline" size="sm">
            <Link to="/attacks">View all attacks</Link>
          </Button>
        }
      />

      <section aria-label="Key figures" className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
        <StatTile
          label="Attacks, 24 h"
          value={s?.sessions}
          delta={attacksDelta}
          hint="Sessions started"
          href="/attacks"
          loading={summary.isPending}
        />
        <StatTile
          label="Unique IPs"
          value={s?.unique_ips}
          hint="Distinct sources"
          href="/attackers"
          loading={summary.isPending}
        />
        <StatTile
          label="Sessions with commands"
          value={s?.sessions_with_commands}
          hint={
            s?.sessions
              ? `${formatPercent(s.sessions_with_commands / s.sessions)} of sessions`
              : "Got a shell"
          }
          href="/attacks"
          loading={summary.isPending}
        />
        <StatTile
          label="Malware attempts"
          value={s?.download_attempts}
          hint="Download commands seen"
          href="/malware"
          loading={summary.isPending}
        />
      </section>

      {/* The activity chart gets the full width (its family legend fits in four columns);
          the rows below pair cards of similar height, so no card is left half empty. */}
      <div className="mt-6">
        <FindingCard
          eyebrow="Activity per sensor, 24 h"
          finding={series.isPending ? "Reading the last 24 hours…" : activity.finding}
          detail={activity.detail}
        >
          <SensorActivityChart points={cur} loading={series.isPending} />
        </FindingCard>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <InsightsCard />
        <FindingCard
          eyebrow="Usernames tried, 24 h"
          finding={
            usernames.isPending
              ? "Counting logins…"
              : describeCredential("username", usernames.data).finding
          }
        >
          <TopList
            items={credentialItems(usernames.data, "username")}
            loading={usernames.isPending}
            empty="No login attempts yet."
          />
        </FindingCard>
        <FindingCard
          eyebrow="Passwords tried, 24 h"
          finding={
            passwords.isPending
              ? "Counting logins…"
              : describeCredential("password", passwords.data).finding
          }
        >
          <TopList
            items={credentialItems(passwords.data, "password")}
            loading={passwords.isPending}
            empty="No login attempts yet."
          />
        </FindingCard>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <FindingCard
          className="lg:col-span-1"
          eyebrow="Top countries, 24 h"
          finding={countries.isPending ? "Locating attackers…" : countryFinding.finding}
          detail={countryFinding.detail}
        >
          <TopList
            items={countryItems}
            loading={countries.isPending}
            rows={6}
            empty="No geolocated events yet."
          />
        </FindingCard>
        <LatestEventsCard className="lg:col-span-2" />
      </div>
    </>
  )
}
