import { useQuery } from "@tanstack/react-query"
import { Users, X } from "lucide-react"
import { useMemo } from "react"
import { FindingCard } from "@/components/finding-card"
import { EmptyState } from "@/components/empty-state"
import { PageHeader } from "@/components/page-header"
import { SkeletonCard } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { JoinCard } from "@/components/network/join-card"
import { MembersList } from "@/components/network/members-list"
import { useNetworkStatus } from "@/components/network/use-network"
import { useUrlParam } from "@/hooks/use-url-param"
import { countryName } from "@/lib/format"
import { isMember, memberName, membersFinding, networkApi, networkKeys } from "@/lib/network"

export function NetworkMembersPage() {
  const status = useNetworkStatus()
  const member = isMember(status.data)
  const [country, setCountry] = useUrlParam("country")
  const summary = useQuery({
    queryKey: networkKeys.summary,
    queryFn: networkApi.summary,
    enabled: member,
  })
  const s = summary.data
  const shown = useMemo(() => {
    const all = s?.members ?? []
    const list = country ? all.filter((m) => m.country === country.toUpperCase()) : [...all]
    // Sorted by name, never by activity: the network has no ranking.
    return list.sort((a, b) =>
      memberName(a).localeCompare(memberName(b), "en", { sensitivity: "base" }),
    )
  }, [s, country])

  return (
    <>
      <PageHeader
        help="network-members"
        title="Members"
        description="Who takes part: a pseudonym, a country if the member chose to show one, and how active the sensor was last week. Never an address."
      />
      {status.isPending || (member && summary.isPending) ? (
        <SkeletonCard />
      ) : !member ? (
        <div className="grid grid-cols-1 gap-4">
          <EmptyState
            icon={Users}
            title="The member list is for members"
            description="Join the network to see who else takes part. Members are listed by pseudonym only."
          />
          <JoinCard />
        </div>
      ) : !s ? (
        <EmptyState
          icon={Users}
          title="The list is on its way"
          description="The network publishes its member list once a day. It shows up here after the next count."
        />
      ) : (
        <FindingCard
          eyebrow="Members"
          finding={
            country
              ? `${shown.length} of ${s.totals.members} members share ${countryName(country) ?? country}.`
              : membersFinding(s.totals)
          }
          detail="Listed by name, not by activity: there is no ranking. A country appears only when the member chose to show it and at least 3 members share it."
          action={
            country ? (
              <Button variant="outline" size="sm" onClick={() => setCountry(null)}>
                <X aria-hidden />
                Clear country filter
              </Button>
            ) : null
          }
          bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0 pt-4"
        >
          {shown.length === 0 ? (
            <div className="border-t p-4 sm:p-5">
              <EmptyState
                variant="bare"
                icon={Users}
                title="No member to show"
                description="No member shows this country."
              />
            </div>
          ) : (
            <MembersList members={shown} />
          )}
        </FindingCard>
      )}
    </>
  )
}
