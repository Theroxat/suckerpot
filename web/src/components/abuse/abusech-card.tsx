import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { TriangleAlert } from "lucide-react"
import { useId, useState } from "react"
import { Field, UnsavedHint } from "@/components/form-parts"
import { useUnsaved } from "@/hooks/use-unsaved"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { ApiError } from "@/lib/api"
import {
  abusechApi,
  abusechKeys,
  CAP_RANGE,
  describeAbusechError,
  HOLD_RANGE,
  KEY_WARNING,
  MODE_EXPLANATION,
  MODE_OPTIONS,
  type AbusechForm,
  type AbusechSettings,
} from "@/lib/abusech"
import { UserError } from "@/lib/users"

type Action = "save" | "remove"

function finding(s: AbusechSettings): string {
  if (!s.server_enabled) return "Submission to abuse.ch is disabled on this server."
  if (s.mode === "off") return "Nothing is submitted to abuse.ch."
  if (s.mode === "review") return "You review each URL before it goes to URLhaus."
  return `New URLs go to URLhaus automatically after ${s.auto_hold_minutes} minutes; ${s.submitted_today} of ${s.daily_cap} sent today.`
}

function toForm(s: AbusechSettings): AbusechForm {
  return {
    mode: s.mode,
    threatfox_enabled: s.threatfox_enabled,
    anonymous: s.anonymous,
    auto_hold_minutes: s.auto_hold_minutes,
    daily_cap: s.daily_cap,
    key: "",
  }
}

async function reauth(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn()
  } catch (e) {
    if (e instanceof ApiError && e.code === "reauth_failed") throw new UserError("wrong-password")
    throw new UserError("invalid", describeAbusechError(e))
  }
}

function AbusechSettingsForm({ initial }: { initial: AbusechSettings }) {
  const qc = useQueryClient()
  const ids = {
    key: useId(),
    hold: useId(),
    cap: useId(),
    fox: useId(),
    anon: useId(),
  }
  const [f, setF] = useState<AbusechForm>(() => toForm(initial))
  const { unsaved, markSaved } = useUnsaved(f)
  const [action, setAction] = useState<Action | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const set = <K extends keyof AbusechForm>(k: K, v: AbusechForm[K]) => {
    setSaved(null)
    setF((p) => ({ ...p, [k]: v }))
  }
  const refresh = () => void qc.invalidateQueries({ queryKey: abusechKeys.all })
  const save = useMutation({ mutationFn: (pw: string) => abusechApi.save(f, pw) })
  const disabled = !initial.server_enabled
  const num = (v: string) => (v === "" ? 0 : Number(v))

  function validate(): string | null {
    if (f.mode === "auto" && !initial.key_set && !f.key)
      return "Automatic submission needs an abuse.ch key."
    if (f.mode === "auto") {
      if (f.auto_hold_minutes < HOLD_RANGE.min || f.auto_hold_minutes > HOLD_RANGE.max)
        return `The waiting time must be between ${HOLD_RANGE.min} and ${HOLD_RANGE.max} minutes.`
      if (f.daily_cap < CAP_RANGE.min || f.daily_cap > CAP_RANGE.max)
        return `The daily limit must be between ${CAP_RANGE.min} and ${CAP_RANGE.max}.`
    }
    return null
  }

  return (
    <div className="grid gap-5">
      {disabled ? (
        <p
          role="note"
          className="flex items-start gap-2.5 rounded-md border border-border-strong bg-surface-raised px-3 py-2.5 text-sm text-fg"
        >
          <TriangleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          Disabled on this server (ABUSECH_SUBMIT_ENABLED). The settings below cannot be used until
          an administrator of the server turns it on.
        </p>
      ) : null}
      <form
        className="grid gap-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          const p = validate()
          setProblem(p)
          if (!p) setAction("save")
        }}
      >
        <div className="space-y-2.5">
          <SegmentedControl
            label="Submission mode"
            value={f.mode}
            onChange={(v) => set("mode", v)}
            options={MODE_OPTIONS.map((o) => ({ ...o, disabled: disabled && o.value !== "off" }))}
          />
          <p className="text-sm text-fg-muted">{MODE_EXPLANATION[f.mode]}</p>
        </div>

        <div className="flex items-start gap-3">
          <Switch
            id={ids.fox}
            checked={f.threatfox_enabled}
            disabled={disabled}
            onCheckedChange={(on) => set("threatfox_enabled", on)}
            className="mt-0.5"
          />
          <label htmlFor={ids.fox} className="text-sm text-fg">
            Also submit command server addresses to ThreatFox
            <span className="block text-xs text-fg-muted">
              Only addresses that a known malware family clearly points to.
            </span>
          </label>
        </div>
        <div className="flex items-start gap-3">
          <Switch
            id={ids.anon}
            checked={f.anonymous}
            disabled={disabled}
            onCheckedChange={(on) => set("anonymous", on)}
            className="mt-0.5"
          />
          <label htmlFor={ids.anon} className="text-sm text-fg">
            Ask abuse.ch to hide the submitter
            <span className="block text-xs text-fg-muted">On by default.</span>
          </label>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <Field
            id={ids.key}
            label="Auth-Key"
            hint={
              initial.key_set
                ? `Set, ending in ${initial.key_last4 ?? "????"}. Leave empty to keep it. ${KEY_WARNING}`
                : `Stored encrypted and never shown again. ${KEY_WARNING}`
            }
          >
            <Input
              id={ids.key}
              type="password"
              autoComplete="new-password"
              disabled={disabled}
              value={f.key}
              placeholder={initial.key_set ? "••••••••" : ""}
              onChange={(e) => set("key", e.target.value)}
            />
          </Field>
          <div className="hidden md:block" />
          {f.mode === "auto" ? (
            <>
              <Field
                id={ids.hold}
                label="Waiting time (minutes)"
                hint={`${HOLD_RANGE.min} to ${HOLD_RANGE.max}. Time to cancel before a URL leaves.`}
              >
                <Input
                  id={ids.hold}
                  inputMode="numeric"
                  value={String(f.auto_hold_minutes)}
                  onChange={(e) => set("auto_hold_minutes", num(e.target.value.replace(/\D/g, "")))}
                />
              </Field>
              <Field
                id={ids.cap}
                label="Daily limit"
                hint={`${CAP_RANGE.min} to ${CAP_RANGE.max} submissions per UTC day.`}
              >
                <Input
                  id={ids.cap}
                  inputMode="numeric"
                  value={String(f.daily_cap)}
                  onChange={(e) => set("daily_cap", num(e.target.value.replace(/\D/g, "")))}
                />
              </Field>
            </>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" disabled={disabled}>
            Save abuse.ch settings
          </Button>
          <UnsavedHint show={unsaved} />
          {initial.key_set ? (
            <Button type="button" variant="ghost" onClick={() => setAction("remove")}>
              Remove the key
            </Button>
          ) : null}
        </div>
        <p role="alert" className="text-sm text-fg empty:hidden">
          {problem}
        </p>
        <p role="status" className="text-sm text-fg-muted empty:hidden">
          {saved}
        </p>
      </form>

      <AdminActionDialog
        hint="Changing the submission settings asks for your own dashboard password again."
        open={action === "save"}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={() => undefined}
        title="Save the abuse.ch settings?"
        description="The key is stored encrypted and never shown again."
        confirmLabel="Save"
        pendingLabel="Saving…"
        run={async (pw) => {
          await reauth(() => save.mutateAsync(pw))
          setSaved("Saved.")
          markSaved(f)
          refresh()
        }}
      />
      <AdminActionDialog
        hint="Removing the key asks for your own dashboard password again."
        open={action === "remove"}
        onOpenChange={(o) => !o && setAction(null)}
        onDone={() => undefined}
        title="Remove the abuse.ch key?"
        description="The key is deleted and submission goes back to Off."
        confirmLabel="Remove"
        pendingLabel="Removing…"
        run={async (pw) => {
          await reauth(() => abusechApi.remove(pw))
          refresh()
        }}
      />
    </div>
  )
}

/** Settings, Reporting tab (administrators only): optional submission of malware URLs to abuse.ch. */
export function AbusechCard() {
  const q = useQuery({ queryKey: abusechKeys.settings, queryFn: abusechApi.settings })
  return (
    <FindingCard
      eyebrow="abuse.ch"
      finding={
        q.isPending
          ? "Loading the abuse.ch settings…"
          : q.isError
            ? "The abuse.ch settings could not be loaded."
            : finding(q.data)
      }
      detail="Optional. SuckerPot shares a captured malware URL with URLhaus only if you choose to."
    >
      {q.isPending ? (
        <SkeletonText lines={4} />
      ) : q.data ? (
        <AbusechSettingsForm
          key={JSON.stringify([q.data.mode, q.data.key_set, q.data.server_enabled])}
          initial={q.data}
        />
      ) : null}
    </FindingCard>
  )
}
