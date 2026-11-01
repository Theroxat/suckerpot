import { useId, useState } from "react"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { Checkbox } from "@/components/ui/checkbox"
import {
  ALL_CONSENTS,
  CONSENTS,
  NETWORK_MESSAGES,
  networkApi,
  RESIDUAL_RISK,
  validatePseudonym,
  type Consent,
} from "@/lib/network"
import { ProfileFields, type Profile } from "./profile-fields"
import { useRefreshNetwork } from "./use-network"

const EMPTY: Profile = { pseudonym: "", country: "", showCountry: false }

/**
 * Joining is a decision, so nothing is pre-ticked: five boxes, each one thing that leaves this
 * system, then the optional pseudonym and country, then the administrator's password again.
 */
export function JoinDialog({
  open,
  onOpenChange,
  onJoined,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onJoined?: () => void
}) {
  const refresh = useRefreshNetwork()
  const [accepted, setAccepted] = useState<ReadonlySet<Consent>>(new Set())
  const [profile, setProfile] = useState<Profile>(EMPTY)
  const [nameError, setNameError] = useState<string | undefined>()
  const group = useId()

  // Closing drops everything typed, so the next opening starts blank: never pre-ticked or filled.
  const reset = () => {
    setAccepted(new Set())
    setProfile(EMPTY)
    setNameError(undefined)
  }

  const toggle = (id: Consent, on: boolean) =>
    setAccepted((prev) => {
      const next = new Set(prev)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })

  return (
    <AdminActionDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
      title="Join the Selfhostr network"
      description="Joining is optional and you can leave at any time with one click. Tick each thing you agree to share."
      hint="Joining asks for your own dashboard password again."
      confirmLabel="Join the network"
      pendingLabel="Joining…"
      validate={() => {
        const problem = validatePseudonym(profile.pseudonym)
        setNameError(problem ?? undefined)
        if (problem) return "Check the pseudonym and try again."
        return ALL_CONSENTS.every((c) => accepted.has(c)) ? null : NETWORK_MESSAGES.consent
      }}
      run={async (password) => {
        await networkApi.join(
          {
            pseudonym: profile.pseudonym,
            country: profile.country,
            showCountry: profile.showCountry,
            accept: ALL_CONSENTS.filter((c) => accepted.has(c)),
          },
          password,
        )
      }}
      onDone={() => {
        void refresh()
        onJoined?.()
      }}
    >
      <fieldset className="flex flex-col gap-3" aria-describedby={`${group}-risk`}>
        <legend className="mb-1 text-sm font-medium text-fg">I agree to share</legend>
        {CONSENTS.map((c) => {
          const id = `${group}-${c.id}`
          return (
            <div key={c.id} className="flex items-start gap-3">
              <Checkbox
                id={id}
                checked={accepted.has(c.id)}
                onCheckedChange={(v) => toggle(c.id, v === true)}
                className="mt-0.5"
              />
              <label htmlFor={id} className="text-sm text-fg">
                {c.title}
                <span className="block text-xs text-fg-muted">{c.shared}</span>
              </label>
            </div>
          )
        })}
        <p id={`${group}-risk`} className="text-xs text-fg-muted">
          Usernames, passwords, commands, ports, exact times and your own address are never sent.{" "}
          {RESIDUAL_RISK}
        </p>
      </fieldset>
      <ProfileFields value={profile} onChange={setProfile} pseudonymError={nameError} />
    </AdminActionDialog>
  )
}
