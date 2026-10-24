import { Card } from "@/components/ui/card"
import { cn } from "@/lib/utils"

interface FindingCardProps {
  /** Small label naming the chart, e.g. "Activity by sensor". */
  eyebrow: string
  /** The plain-English finding the chart proves. Mandatory: no chart without a sentence. */
  finding: React.ReactNode
  /** Optional supporting line under the finding. */
  detail?: React.ReactNode
  /** Right-aligned controls (period switch, "View all" link…). */
  action?: React.ReactNode
  footer?: React.ReactNode
  children?: React.ReactNode
  className?: string
  bodyClassName?: string
}

/** The base Card: a finding sentence first, then the evidence. */
export function FindingCard({
  eyebrow,
  finding,
  detail,
  action,
  footer,
  children,
  className,
  bodyClassName,
}: FindingCardProps) {
  return (
    <Card className={cn("gap-0 rounded-lg py-0 shadow-sm", className)}>
      <header className="flex items-start justify-between gap-4 px-4 pt-4 sm:px-5 sm:pt-5">
        <div className="min-w-0 space-y-1.5">
          <p className="text-xs font-medium text-fg-muted">{eyebrow}</p>
          <h3 className="text-base font-medium text-pretty text-fg">{finding}</h3>
          {detail ? <p className="text-sm text-fg-muted">{detail}</p> : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </header>
      {children ? (
        <div className={cn("px-4 pt-4 pb-4 sm:px-5 sm:pb-5", bodyClassName)}>{children}</div>
      ) : (
        <div className="pb-4 sm:pb-5" />
      )}
      {footer ? (
        <footer className="border-t px-4 py-3 text-xs text-fg-muted sm:px-5">{footer}</footer>
      ) : null}
    </Card>
  )
}
