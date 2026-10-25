import { useIpMask } from "@/app/ip-mask"
import { CopyButton } from "@/components/defend/copy-button"
import { maskIpsInText } from "@/lib/format"
import { cn } from "@/lib/utils"

/**
 * Monospace text with a copy button. Always rendered as plain text, never as HTML: rule text and
 * values come from attacker traffic. Addresses are masked, and copying is off, in screenshot mode.
 */
export function CodeBlock({
  text,
  label,
  caption,
  className,
}: {
  text: string
  /** Accessible name of the block, e.g. "Sigma rule". */
  label: string
  caption?: string
  className?: string
}) {
  const { masked } = useIpMask()
  return (
    <figure className={cn("overflow-hidden rounded-md border bg-bg", className)}>
      <figcaption className="flex items-center justify-between gap-2 border-b px-3 py-1.5 text-xs text-fg-muted">
        <span className="truncate">{caption ?? label}</span>
        {masked ? null : <CopyButton text={text} label={`Copy ${label}`} />}
      </figcaption>
      <pre
        tabIndex={0}
        aria-label={label}
        className="max-h-80 overflow-auto px-3 py-2.5 font-mono text-xs leading-5 whitespace-pre text-fg"
      >
        <code>{masked ? maskIpsInText(text) : text}</code>
      </pre>
    </figure>
  )
}
