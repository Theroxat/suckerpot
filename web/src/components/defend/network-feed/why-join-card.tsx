import { Link } from "react-router"
import { FindingCard } from "@/components/finding-card"
import { Button } from "@/components/ui/button"
import { plural } from "@/lib/format"
import type { FeedStatus } from "@/lib/network-feed"

/** Honest wording: the lists are the same for everyone, joining only helps them grow. */
export function WhyJoinCard({ status }: { status: FeedStatus }) {
  if (status.member) {
    const helped = status.lists.reduce((n, l) => n + (l.helped ?? 0), 0)
    return (
      <FindingCard
        eyebrow="Your part"
        finding={
          helped > 0
            ? `Your sensor helped confirm ${plural(helped, "entry", "entries")} on these lists.`
            : "Your sensor is a member, but has not helped confirm an entry yet."
        }
        detail="Entries your sensor helped confirm carry a You helped badge in the table. Every firewall gets the same lists, whether or not it joined."
        action={
          <Button asChild variant="outline" size="sm">
            <Link to="/network">Open the network</Link>
          </Button>
        }
      />
    )
  }
  return (
    <FindingCard
      eyebrow="Why join the network?"
      finding="These lists are free and public. Every firewall gets the same lists, whether or not you join."
      detail="Joining adds your sensor to the ones that confirm entries, so the lists get faster and more accurate, and you see which entries your sensor helped confirm. Nothing is shared until you join."
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/network">About the network</Link>
        </Button>
      }
    />
  )
}
