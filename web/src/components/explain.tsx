import { Term } from "@/components/term"
import type { TermId } from "@/lib/glossary"

interface ExplainProps {
  /** Glossary id, for example "brute-force". */
  term: TermId
  /** The words to show; defaults to the glossary's own word. */
  children?: React.ReactNode
  className?: string
}

/**
 * Underlines a word and shows its plain-English definition on hover, focus or tap. This is the
 * wording used on the Today page; it shares the glossary and the popover with `Term`.
 */
export function Explain({ term, children, className }: ExplainProps) {
  return (
    <Term id={term} className={className}>
      {children}
    </Term>
  )
}
