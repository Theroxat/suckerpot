import { Link } from "react-router"
import { CountryFlag } from "@/components/country-flag"
import { IPChip } from "@/components/ip-chip"
import { RelativeTime } from "@/components/relative-time"
import { ScannerBadge } from "@/components/scanner-badge"
import { SensorBadge } from "@/components/sensor-badge"
import { SessionStory } from "@/components/session-story"
import { SeverityBadge } from "@/components/severity-badge"
import { TagBadge } from "@/components/tag-badge"
import type { Session } from "@/lib/api"
import { describeSession, describeSessionText } from "@/lib/describe-session"
import { sessionSeverity } from "@/lib/severity"
import { cn } from "@/lib/utils"

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1)
}

interface SessionRowProps {
  session: Session
  masked?: boolean
  /** Hide the address and origin, e.g. on an attacker profile where they are all the same. */
  showSource?: boolean
  className?: string
}

/**
 * One session as one line. The whole row opens the session (stretched link);
 * the IP, flag and tags stay independently clickable above it.
 */
export function SessionRow({ session, masked, showSource = true, className }: SessionRowProps) {
  const severity = sessionSeverity(session)
  const flagged = severity === "warning" || severity === "severe"

  return (
    <div
      className={cn(
        "group/row relative grid grid-cols-1 items-center gap-y-1.5 px-4 py-3 transition-colors duration-150 hover:bg-surface-hover/50 sm:px-5",
        "md:grid-cols-[5.5rem_minmax(0,1fr)_auto_6rem] md:gap-x-4",
        className,
      )}
    >
      <Link
        to={`/attacks/${encodeURIComponent(session.session_id)}`}
        className="absolute inset-0 rounded-[inherit] focus-visible:outline-offset-[-2px]"
        aria-label={describeSessionText(session)}
      />
      {/* Mobile (< md): two lines. Badge, address and time first; the story below. */}
      <div className="flex min-w-0 items-center gap-2.5 md:hidden">
        <SensorBadge sensor={session.sensor} />
        {showSource ? (
          <>
            <IPChip
              ip={session.src_ip}
              masked={masked}
              variant="ghost"
              className="relative z-10 ml-0"
            />
            {session.country ? (
              <CountryFlag code={session.country} className="relative z-10" />
            ) : null}
          </>
        ) : null}
        <span className="ml-auto flex shrink-0 items-center gap-2">
          {session.benign ? <ScannerBadge name={session.scanner_name} short /> : null}
          {flagged ? <SeverityBadge severity={severity} iconOnly /> : null}
          <RelativeTime iso={session.started_at} className="relative z-10 text-xs" />
        </span>
      </div>
      <p className="line-clamp-2 text-fg md:hidden">{describeSession(session).predicate}</p>

      {/* Desktop: one line. */}
      <SensorBadge sensor={session.sensor} className="hidden justify-self-start md:inline-flex" />
      {showSource ? (
        <SessionStory
          session={session}
          masked={masked}
          className="hidden md:flex"
          layout="inline"
          ipVariant="ghost"
          ipClassName="w-36"
        />
      ) : (
        <p className="hidden truncate text-fg md:block">
          {capitalize(describeSession(session).predicate)}
        </p>
      )}

      <div className="hidden items-center justify-end gap-1.5 md:flex">
        {session.benign ? <ScannerBadge name={session.scanner_name} className="z-10" /> : null}
        {/* The scanner badge already says it: the rules engine's "scanner" tag would repeat it. */}
        {(session.benign ? session.tags.filter((t) => t !== "scanner") : session.tags)
          .slice(0, 2)
          .map((t) => (
            <TagBadge key={t} tag={t} className="z-10" />
          ))}
        {flagged ? <SeverityBadge severity={severity} iconOnly className="z-10" /> : null}
      </div>
      <div className="hidden justify-self-end md:block">
        <RelativeTime iso={session.started_at} className="relative z-10 text-xs" />
      </div>
    </div>
  )
}
