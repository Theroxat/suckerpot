import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Eye, EyeOff, Trash2 } from "lucide-react"
import { useId, useState } from "react"
import { useSearchParams } from "react-router"
import { Field, FormError } from "@/components/form-parts"
import { FindingCard } from "@/components/finding-card"
import { SegmentedControl } from "@/components/segmented-control"
import { SkeletonText } from "@/components/skeletons"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import {
  abuseApi,
  abuseKeys,
  describeAbuseError,
  guardReason,
  guardReasonsOf,
  isStale,
  TLP_OPTIONS,
  type ReportSettings,
  type SelfTerm,
  type Tlp,
} from "@/lib/abuse"
import { plural } from "@/lib/format"

const blank = (v: string): string | null => (v.trim() === "" ? null : v.trim())

function Toggle({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string
  hint: string
  checked: boolean
  onChange: (on: boolean) => void
}) {
  const id = useId()
  return (
    <div className="flex items-start gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onChange} className="mt-0.5" />
      <label htmlFor={id} className="text-sm text-fg">
        {label}
        <span className="block text-xs text-fg-muted">{hint}</span>
      </label>
    </div>
  )
}

function SettingsForm({
  initial,
  onStale,
  onSaved,
}: {
  initial: ReportSettings
  onStale: () => void
  onSaved: () => void
}) {
  const qc = useQueryClient()
  const ids = {
    reply: useId(),
    sig: useId(),
    intro: useId(),
    outro: useId(),
    ua: useId(),
    note: useId(),
    subj: useId(),
    err: useId(),
  }
  const [s, setS] = useState(initial)
  const [params] = useSearchParams()
  const flagged = new Set((params.get("missing") ?? "").split(",").filter(Boolean))
  // The server names the reply contact when it is the one thing missing; it stays flagged until set.
  const needContact =
    flagged.has("reply_contact") && !(s.reply_contact ?? "").trim()
      ? "Required: reports need a way to be answered."
      : undefined
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const save = useMutation({
    mutationFn: () => abuseApi.saveSettings(s),
    onSuccess: (d) => {
      onSaved()
      setError(null)
      setSaved(true)
      qc.setQueryData(abuseKeys.settings, d)
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
    },
    onError: (e) => {
      setSaved(false)
      if (isStale(e)) {
        onStale()
        return
      }
      const why = guardReasonsOf(e)
      setError(
        why
          ? (why.length > 0 ? why : ["unknown"]).map(guardReason).join(" ")
          : describeAbuseError(e),
      )
    },
  })
  const set = <K extends keyof ReportSettings>(k: K, v: ReportSettings[K]) => {
    setSaved(false)
    setS((p) => ({ ...p, [k]: v }))
  }
  return (
    <form
      className="grid gap-6"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate()
      }}
    >
      <div className="grid gap-4 md:grid-cols-2">
        <Field
          id={ids.reply}
          label="Reply contact"
          hint="Required. A mailbox that does not point to you, so the recipient can answer."
          error={needContact}
        >
          <Input
            id={ids.reply}
            type="email"
            maxLength={254}
            autoComplete="off"
            value={s.reply_contact ?? ""}
            placeholder="reports@example.net"
            onChange={(e) => set("reply_contact", blank(e.target.value))}
          />
        </Field>
        <Field
          id={ids.sig}
          label="Signature"
          optional
          hint="One line at the end of the message. Leave empty to send only the facts."
        >
          <Input
            id={ids.sig}
            maxLength={200}
            autoComplete="off"
            value={s.signature ?? ""}
            onChange={(e) => set("signature", blank(e.target.value))}
          />
        </Field>
        <Field
          id={ids.intro}
          label="Introduction"
          optional
          hint="Shown before the facts. Leave empty to send only the facts."
        >
          <Textarea
            id={ids.intro}
            rows={3}
            maxLength={1000}
            value={s.intro ?? ""}
            onChange={(e) => set("intro", blank(e.target.value))}
          />
        </Field>
        <Field
          id={ids.outro}
          label="Closing"
          optional
          hint="Shown after the facts. Leave empty to send only the facts."
        >
          <Textarea
            id={ids.outro}
            rows={3}
            maxLength={1000}
            value={s.outro ?? ""}
            onChange={(e) => set("outro", blank(e.target.value))}
          />
        </Field>
        <Field
          id={ids.ua}
          label="X-ARF user agent"
          optional
          hint="Sent in X-ARF reports. Leave empty to use a generic value (Mozilla/5.0)."
        >
          <Input
            id={ids.ua}
            maxLength={64}
            autoComplete="off"
            value={s.xarf_user_agent ?? ""}
            className="font-mono"
            onChange={(e) => set("xarf_user_agent", blank(e.target.value))}
          />
        </Field>
        <Field
          id={ids.note}
          label="Note about the destination and ports"
          optional
          hint="For example that the destination address is withheld. Leave empty to send only the facts."
        >
          <Textarea
            id={ids.note}
            rows={3}
            maxLength={1000}
            value={s.note ?? ""}
            onChange={(e) => set("note", blank(e.target.value))}
          />
        </Field>
        <Field
          id={ids.subj}
          label="Subject template"
          optional
          hint="Leave empty to use the plain subject Abuse report for {value}."
        >
          <Input
            id={ids.subj}
            maxLength={200}
            autoComplete="off"
            value={s.subject_template ?? ""}
            onChange={(e) => set("subject_template", blank(e.target.value))}
          />
        </Field>
        <div className="flex flex-col gap-1.5">
          <span className="text-sm font-medium text-fg">
            Default sharing level for CERT exports
          </span>
          <SegmentedControl
            label="Default sharing level"
            value={s.default_tlp}
            onChange={(v: Tlp) => set("default_tlp", v)}
            options={TLP_OPTIONS}
            className="self-start"
          />
        </div>
      </div>
      <fieldset className="grid gap-3">
        <legend className="mb-1 text-sm font-medium text-fg">Defaults for new drafts</legend>
        <Toggle
          label="Round times to the minute"
          hint="On by default. Exact seconds make it easier to match flow logs, and so to recognise you."
          checked={s.round_times}
          onChange={(on) => set("round_times", on)}
        />
        <Toggle
          label="Defang URLs and addresses"
          hint="hxxp://203.0.113[.]9 instead of a live link."
          checked={s.default_options.defang}
          onChange={(on) => set("default_options", { ...s.default_options, defang: on })}
        />
        <Toggle
          label="Include the usernames tried"
          hint="Never the passwords."
          checked={s.default_options.include_usernames}
          onChange={(on) => set("default_options", { ...s.default_options, include_usernames: on })}
        />
        <Toggle
          label="Include the reply contact"
          hint="Only when a reply contact is set."
          checked={s.default_options.include_reply_contact}
          onChange={(on) =>
            set("default_options", { ...s.default_options, include_reply_contact: on })
          }
        />
        <Toggle
          label="Add the redaction counter line"
          hint="How many values were masked and lines left out. Off by default."
          checked={s.default_options.show_redaction_counts}
          onChange={(on) =>
            set("default_options", { ...s.default_options, show_redaction_counts: on })
          }
        />
      </fieldset>
      <FormError id={ids.err} message={error} />
      <div className="flex items-center gap-3">
        <Button type="submit" size="sm" disabled={save.isPending}>
          {save.isPending ? "Saving…" : "Save"}
        </Button>
        <span role="status" className="text-sm text-fg-muted empty:hidden">
          {saved ? "Saved." : null}
        </span>
      </div>
    </form>
  )
}

/** Text the reports must never contain: learned from traffic, or added by hand. */
export function NeverInReport() {
  const qc = useQueryClient()
  const [reveal, setReveal] = useState(false)
  const [kind, setKind] = useState<SelfTerm["kind"]>("address")
  const [value, setValue] = useState("")
  const [error, setError] = useState<string | null>(null)
  const id = useId()
  const q = useQuery({ queryKey: abuseKeys.terms(reveal), queryFn: () => abuseApi.terms(reveal) })
  const refresh = () => void qc.invalidateQueries({ queryKey: ["abuse", "terms"] })
  const fail = (e: unknown) => setError(describeAbuseError(e))
  const add = useMutation({
    mutationFn: () => abuseApi.addTerm(kind, value.trim()),
    onSuccess: () => {
      setValue("")
      setError(null)
      refresh()
    },
    onError: fail,
  })
  const confirm = useMutation({
    mutationFn: abuseApi.confirmTerm,
    onSuccess: refresh,
    onError: fail,
  })
  const del = useMutation({ mutationFn: abuseApi.deleteTerm, onSuccess: refresh, onError: fail })
  const terms = q.data ?? []
  return (
    <FindingCard
      eyebrow="Never in a report"
      finding={
        q.isPending
          ? "Checking what reports must never contain…"
          : terms.some((t) => t.confirmed)
            ? `${plural(terms.filter((t) => t.confirmed).length, "term")} ${terms.filter((t) => t.confirmed).length === 1 ? "is" : "are"} checked for in every report, and the report is blocked if one appears.${pendingTerms(terms)}`
            : "Nothing is known yet, so reports stay locked until traffic teaches the address of the monitored system, or you add it here."
      }
      action={
        <Button variant="outline" size="sm" onClick={() => setReveal((r) => !r)}>
          {reveal ? <EyeOff aria-hidden /> : <Eye aria-hidden />}
          {reveal ? "Hide values" : "Reveal values"}
        </Button>
      }
      bodyClassName="px-0 sm:px-0 pb-0 sm:pb-0"
    >
      {q.isPending ? (
        <div className="px-4 sm:px-5">
          <SkeletonText lines={3} />
        </div>
      ) : (
        <>
          <p className="border-t px-4 py-3 text-xs text-fg-muted sm:px-5">
            A learned term does nothing until you confirm it: an attacker can plant text in traffic
            to make a report refuse a word. Confirm only what is yours.
          </p>
          <ul className="divide-y border-t">
            {terms.map((t) => (
              <li
                key={t.id}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 sm:px-5"
              >
                <code className="font-mono text-xs text-fg">{t.value}</code>
                <span className="text-xs text-fg-muted">
                  {t.kind} ·{" "}
                  {t.source === "learned"
                    ? `learned from traffic (${plural(t.distinct_sources, "source")})`
                    : t.source === "sensor"
                      ? "declared by a sensor"
                      : "added by hand"}
                  {t.confirmed ? "" : " · inactive until you confirm it"}
                </span>
                <span className="ml-auto flex gap-2">
                  {!t.confirmed ? (
                    <Button size="xs" variant="outline" onClick={() => confirm.mutate(t.id)}>
                      Confirm
                    </Button>
                  ) : null}
                  {t.source !== "sensor" ? (
                    <Button
                      size="icon-xs"
                      variant="ghost"
                      aria-label={`Delete ${t.value}`}
                      onClick={() => del.mutate(t.id)}
                    >
                      <Trash2 aria-hidden />
                    </Button>
                  ) : null}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
      <form
        className="flex flex-wrap items-end gap-3 border-t px-4 py-4 sm:px-5"
        onSubmit={(e) => {
          e.preventDefault()
          if (value.trim().length < 2) {
            setError("Enter at least two characters.")
            return
          }
          add.mutate()
        }}
      >
        <div className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-fg-muted">Add</span>
          <SegmentedControl
            label="Kind"
            value={kind}
            onChange={setKind}
            options={[
              { value: "address", label: "Address" },
              { value: "cidr", label: "Network" },
              { value: "name", label: "Name" },
              { value: "text", label: "Text" },
            ]}
          />
        </div>
        <div className="flex min-w-48 flex-1 flex-col gap-1.5">
          <label htmlFor={id} className="text-xs font-medium text-fg-muted">
            Value
          </label>
          <Input
            id={id}
            autoComplete="off"
            value={value}
            maxLength={253}
            className="font-mono"
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <Button type="submit" size="sm" variant="outline" disabled={add.isPending}>
          Add
        </Button>
        <p role="alert" className="w-full text-sm text-fg empty:hidden">
          {error}
        </p>
      </form>
    </FindingCard>
  )
}

/** Settings, Reporting tab (administrators only): the wording and defaults of the drafts. */
export function ReportingCard() {
  const q = useQuery({ queryKey: abuseKeys.settings, queryFn: abuseApi.settings })
  const [stale, setStale] = useState(false)
  return (
    <>
      <FindingCard
        eyebrow="Reporting"
        finding={
          q.isPending
            ? "Loading the reporting settings…"
            : q.isError
              ? "The reporting settings could not be loaded."
              : q.data.reply_contact
                ? "Reports are ready to write. The texts around the facts are optional."
                : "Set a reply contact so reports can be answered. The texts are optional."
        }
        detail="Saving these words sends nothing. By default you copy a draft into your own mailbox; SMTP sending is optional, further down."
      >
        {q.isPending ? (
          <SkeletonText lines={4} />
        ) : q.data ? (
          <>
            {stale ? (
              <p role="alert" className="mb-4 text-sm text-fg">
                The settings were changed somewhere else, so they were reloaded. Read them again,
                then save your edit.
              </p>
            ) : null}
            <SettingsForm
              key={q.data.revision}
              initial={q.data}
              onSaved={() => setStale(false)}
              onStale={() => {
                setStale(true)
                void q.refetch()
              }}
            />
          </>
        ) : null}
      </FindingCard>
      <NeverInReport />
    </>
  )
}

/** " 1 learned term waits for your confirmation." or nothing. */
function pendingTerms(terms: { confirmed: boolean }[]): string {
  const n = terms.filter((t) => !t.confirmed).length
  if (n === 0) return ""
  return ` ${plural(n, "learned term")} ${n === 1 ? "waits" : "wait"} for your confirmation.`
}
