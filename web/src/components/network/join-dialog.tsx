import { ChevronRight } from "lucide-react"
import { useId, useState } from "react"
import { AdminActionDialog } from "@/components/users/admin-action-dialog"
import { ALL_CONSENTS, networkApi, validatePseudonym } from "@/lib/network"
import { ProfileFields, type Profile } from "./profile-fields"
import { useRefreshNetwork } from "./use-network"
import { WhatYouShare } from "./what-you-share"

const EMPTY: Profile = { pseudonym: "", country: "", showCountry: false }

/**
 * Joining is one button and the password. The five consents are shown as a read-only list and all
 * five are sent. The pseudonym and country are optional and stay collapsed.
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
  const [profile, setProfile] = useState<Profile>(EMPTY)
  const [nameError, setNameError] = useState<string | undefined>()
  const [more, setMore] = useState(false)
  const group = useId()

  // Closing drops everything typed, so the next opening starts blank.
  const reset = () => {
    setProfile(EMPTY)
    setNameError(undefined)
    setMore(false)
  }

  return (
    <AdminActionDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
      title="Join the Selfhostr network"
      description="Help the network take down attack sources. You can leave at any time with one button."
      hint="Joining asks for your own dashboard password again."
      focusPassword={false}
      confirmLabel="Join the network"
      pendingLabel="Joining…"
      validate={() => {
        const problem = validatePseudonym(profile.pseudonym)
        setNameError(problem ?? undefined)
        if (problem) {
          setMore(true)
          return "Check the pseudonym and try again."
        }
        return null
      }}
      run={async (password) => {
        await networkApi.join(
          {
            pseudonym: profile.pseudonym,
            country: profile.country,
            showCountry: profile.showCountry,
            accept: [...ALL_CONSENTS],
          },
          password,
        )
      }}
      onDone={() => {
        void refresh()
        onJoined?.()
      }}
    >
      <WhatYouShare />
      <div className="space-y-3">
        <button
          type="button"
          onClick={() => setMore((v) => !v)}
          aria-expanded={more}
          aria-controls={`${group}-profile`}
          className="flex items-center gap-1.5 rounded-sm text-sm font-medium text-fg-muted hover:text-fg focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <ChevronRight
            aria-hidden
            className={
              more ? "size-4 rotate-90 transition-transform" : "size-4 transition-transform"
            }
          />
          Optional: pseudonym and country
        </button>
        <div id={`${group}-profile`} hidden={!more}>
          <ProfileFields value={profile} onChange={setProfile} pseudonymError={nameError} />
        </div>
      </div>
    </AdminActionDialog>
  )
}
