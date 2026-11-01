import { Link } from "react-router"
import { useVersion } from "@/hooks/use-version"
import { hasUpdate } from "@/lib/version"
import { cn } from "@/lib/utils"

/**
 * The small version line at the foot of the navigation. When a release is available it adds a
 * dot and a words-first link to the Updates card, so the cue never rests on the dot alone.
 */
export function VersionLabel({
  onNavigate,
  className,
}: {
  onNavigate?: () => void
  className?: string
}) {
  const q = useVersion()
  const v = q.data
  if (!v) return null
  return (
    <div className={cn("flex flex-col gap-1 px-1 text-2xs text-fg-subtle", className)}>
      <span className="font-mono tabular-nums" title={v.commit ? `Commit ${v.commit}` : undefined}>
        {v.version}
      </span>
      {hasUpdate(v) ? (
        <Link
          to="/settings"
          onClick={onNavigate}
          className="inline-flex items-center gap-1.5 rounded-sm text-xs font-medium text-fg underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <span aria-hidden className="size-1.5 rounded-full bg-primary" />
          Update available: {v.latest}
        </Link>
      ) : null}
    </div>
  )
}
