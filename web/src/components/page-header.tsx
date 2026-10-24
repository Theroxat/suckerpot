import { cn } from "@/lib/utils"

interface PageHeaderProps {
  title: string
  /** One sentence that says what this page shows right now. */
  description?: React.ReactNode
  actions?: React.ReactNode
  /** Breadcrumb or back link above the title. */
  eyebrow?: React.ReactNode
  className?: string
}

export function PageHeader({ title, description, actions, eyebrow, className }: PageHeaderProps) {
  return (
    <header
      className={cn(
        "flex flex-col gap-4 pb-6 sm:flex-row sm:items-end sm:justify-between sm:gap-6",
        className,
      )}
    >
      <div className="min-w-0 space-y-1.5">
        {eyebrow ? <div className="text-xs text-fg-muted">{eyebrow}</div> : null}
        <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
        {description ? (
          <p className="max-w-2xl text-base text-pretty text-fg-muted">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </header>
  )
}
