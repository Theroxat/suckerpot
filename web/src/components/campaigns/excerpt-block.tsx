import { ArrowDownToLine, KeyRound, SquareTerminal, Globe, type LucideIcon } from "lucide-react"
import { useIpMask } from "@/app/ip-mask"
import { maskIpsInText } from "@/lib/format"
import type { Excerpt, ExcerptLine } from "@/lib/campaigns"
import { cn } from "@/lib/utils"

const KIND: Record<ExcerptLine["kind"], { icon: LucideIcon; label: string }> = {
  login: { icon: KeyRound, label: "Login" },
  command: { icon: SquareTerminal, label: "Command" },
  request: { icon: Globe, label: "Request" },
  download: { icon: ArrowDownToLine, label: "Download" },
}

/**
 * A few real lines from one session of the campaign, as recorded. Text only: nothing in it is
 * a link or is ever run. Addresses are masked in screenshot mode.
 */
export function ExcerptBlock({ excerpt, className }: { excerpt: Excerpt; className?: string }) {
  const { masked } = useIpMask()
  return (
    <ol
      aria-label="Lines from a real session"
      className={cn(
        "divide-y overflow-hidden rounded-md border bg-bg font-mono text-xs",
        className,
      )}
    >
      {excerpt.lines.map((line, i) => {
        const { icon: Icon, label } = KIND[line.kind]
        return (
          <li
            key={`${i}-${line.text}`}
            style={{ animationDelay: `${i * 35}ms` }}
            className="flex animate-fade-in items-start gap-2.5 px-3 py-2"
          >
            <Icon aria-hidden className="mt-0.5 size-3.5 shrink-0 text-fg-subtle" />
            <span className="sr-only">{label}: </span>
            <span className="min-w-0 break-all whitespace-pre-wrap text-fg">
              {masked ? maskIpsInText(line.text) : line.text}
            </span>
          </li>
        )
      })}
    </ol>
  )
}
