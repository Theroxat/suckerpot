import { Link } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { SeverityBadge } from "@/components/severity-badge"
import { maskIpsInText } from "@/lib/format"
import type { ExplainedLine } from "@/lib/scripts"

/**
 * The script, one command per row, each with what it does in plain words. Commands are text
 * only (never links); a technique opens the scripts that share it.
 */
export function ExplainedLines({ lines }: { lines: readonly ExplainedLine[] }) {
  const { masked } = useIpMask()
  return (
    <ol aria-label="Commands with explanations" className="divide-y">
      {lines.map((l) => {
        const command = l.raw ?? l.text
        return (
          <li
            key={l.n}
            className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-2 py-3 first:pt-0 last:pb-0 sm:grid-cols-[2rem_minmax(0,1fr)_auto]"
          >
            <span className="pt-0.5 text-right font-mono text-xs text-fg-subtle tabular-nums">
              {l.n}
            </span>
            <div className="min-w-0 space-y-1.5">
              <code className="block font-mono text-xs/5 [overflow-wrap:anywhere] whitespace-pre-wrap text-fg">
                {masked ? maskIpsInText(command) : command}
              </code>
              <p className={l.risk ? "text-sm text-fg-muted" : "text-sm text-fg-subtle italic"}>
                {l.explanation}
              </p>
              {l.technique ? (
                <Link
                  to={`/scripts?technique=${encodeURIComponent(l.technique)}`}
                  className="inline-flex items-center gap-1.5 rounded-sm border border-border-strong px-1.5 py-0.5 text-2xs text-fg-muted transition-colors hover:border-fg-subtle hover:text-fg"
                >
                  <span className="font-mono">{l.technique}</span>
                  {l.technique_name ? <span>{l.technique_name}</span> : null}
                </Link>
              ) : null}
            </div>
            <div className="col-start-2 pt-1 sm:col-start-auto sm:pt-0">
              {l.risk ? <SeverityBadge severity={l.risk} /> : null}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
