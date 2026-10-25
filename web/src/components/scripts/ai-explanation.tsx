import { useMutation, useQueryClient } from "@tanstack/react-query"
import { Loader2, Sparkles } from "lucide-react"
import { useAuth } from "@/app/auth"
import { FindingCard } from "@/components/finding-card"
import { RelativeTime } from "@/components/relative-time"
import { Button } from "@/components/ui/button"
import { ApiError } from "@/lib/api"
import {
  llmRequestMessage,
  llmUnavailable,
  scriptKeys,
  scriptsApi,
  type AiExplanation,
  type LlmState,
} from "@/lib/scripts"

/** The label every model-written text carries. Always visible, never collapsed. */
export function AiLabel({ model }: { model: string | null }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-sm border border-border-strong px-2 py-0.5 text-2xs font-medium text-fg-muted">
      <Sparkles aria-hidden className="size-3" />
      AI-generated, may be wrong
      {model ? <span className="font-mono text-fg-subtle">{model}</span> : null}
    </span>
  )
}

/**
 * The optional second opinion from a language model. It must never pass for the built-in
 * explanation: a dashed border (the "not ours" surface), the AI label always in the header, and
 * muted text only, so it never reads louder than the rule-based lines above. Everything it wrote
 * is rendered as plain text (React escapes it; nothing here uses innerHTML or turns text into
 * links).
 */
export function AiExplanationCard({
  ai,
  llm,
  scriptId,
}: {
  ai: AiExplanation | null
  llm: LlmState
  scriptId: number
}) {
  const { canWrite } = useAuth()
  const queryClient = useQueryClient()
  const ask = useMutation({
    mutationFn: () => scriptsApi.explain(scriptId),
    onSettled: () => queryClient.invalidateQueries({ queryKey: scriptKeys.detail(scriptId) }),
  })
  const queued = llm.request_state === "queued" || ask.isPending
  const note = llmRequestMessage(llm)

  if (!ai && !llm.available) {
    return (
      <p className="flex items-start gap-2 text-sm text-fg-muted normal-nums">
        <Sparkles aria-hidden className="mt-0.5 size-4 shrink-0" />
        <span>{llmUnavailable(llm)}</span>
      </p>
    )
  }

  return (
    <FindingCard
      eyebrow="Second opinion"
      finding={
        ai
          ? "A language model explained this script too."
          : "Ask a language model to explain this script."
      }
      detail={
        ai
          ? undefined
          : "Only the cleaned-up command text is sent: no addresses, no host names, no session data."
      }
      action={<AiLabel model={ai?.model ?? llm.model} />}
      className="border-dashed border-border-strong normal-nums shadow-none"
    >
      {ai ? (
        <div className="animate-fade-in space-y-3">
          <p className="max-w-3xl text-sm text-pretty text-fg-muted">{ai.summary}</p>
          <ol aria-label="AI explanation, line by line" className="space-y-1.5">
            {ai.lines.map((l) => (
              <li
                key={l.n}
                className="grid grid-cols-[1.5rem_minmax(0,1fr)] gap-x-2.5 text-sm sm:grid-cols-[2rem_minmax(0,1fr)] sm:gap-x-3"
              >
                <span className="text-right font-mono text-xs/5 text-fg-subtle tabular-nums">
                  {l.n}
                </span>
                <span className="max-w-3xl text-pretty text-fg-muted">{l.explanation}</span>
              </li>
            ))}
          </ol>
          <p className="text-xs text-fg-subtle">
            Written <RelativeTime iso={ai.created_at} className="text-xs text-fg-subtle" />. It can
            be wrong: check it against the built-in explanation above.
          </p>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          {canWrite ? (
            <Button size="sm" disabled={queued} onClick={() => ask.mutate()}>
              {queued ? (
                <Loader2 aria-hidden className="size-3.5 animate-spin motion-reduce:animate-none" />
              ) : (
                <Sparkles aria-hidden className="size-3.5" />
              )}
              {queued ? "Explaining…" : "Explain now"}
            </Button>
          ) : (
            <p className="text-sm text-fg-muted">Only an administrator can ask for this.</p>
          )}
          <p role="status" className="text-sm text-fg-muted">
            {ask.isError
              ? ask.error instanceof ApiError
                ? ask.error.message
                : "The request could not be sent."
              : note}
          </p>
        </div>
      )}
    </FindingCard>
  )
}
