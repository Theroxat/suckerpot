import { CircleAlert } from "lucide-react"
import type { ReactNode } from "react"

/** A labelled form field with a hint, or an error that replaces the hint. */
export function Field({
  id,
  label,
  hint,
  error,
  children,
}: {
  id: string
  label: string
  hint?: string
  error?: string | undefined
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-fg">
        {label}
      </label>
      {children}
      {error ? (
        <p id={`${id}-error`} className="flex items-start gap-1.5 text-xs text-fg">
          <CircleAlert aria-hidden className="mt-0.5 size-3 shrink-0 text-fg-muted" />
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-xs text-fg-muted">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export function FormError({ id, message }: { id: string; message: string | null }) {
  return (
    <div id={id} role="alert" aria-live="assertive" className="empty:hidden">
      {message ? (
        <p className="flex items-start gap-2 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg">
          <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          {message}
        </p>
      ) : null}
    </div>
  )
}
