import { useQueryClient } from "@tanstack/react-query"
import { useId, useState, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { classifyFailure, deleteOverride, describeDefendError } from "@/lib/defend"

export interface RemovingOverride {
  id: number
  /** The value, as shown to the person. */
  label: string
}

function RemoveForm({
  target,
  onDone,
  onCancel,
}: {
  target: RemovingOverride
  onDone: () => void
  onCancel: () => void
}) {
  const queryClient = useQueryClient()
  const [password, setPassword] = useState("")
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { pass: useId(), err: useId() }

  async function submit() {
    if (pending) return
    setError(null)
    setPasswordError(null)
    if (!password) {
      setPasswordError("Enter your password to confirm.")
      return
    }
    setPending(true)
    try {
      await deleteOverride(target.id, password)
      await queryClient.invalidateQueries({ queryKey: ["defend"] })
      onDone()
    } catch (e) {
      if (classifyFailure(e) === "wrong-password") setPasswordError(describeDefendError(e))
      else setError(describeDefendError(e))
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      onSubmit={(event: SyntheticEvent) => {
        event.preventDefault()
        void submit()
      }}
      className="flex flex-col gap-4"
      noValidate
    >
      <DialogHeader className="text-left">
        <DialogTitle>Remove this override?</DialogTitle>
        <DialogDescription>
          The score decides again for{" "}
          <span className="font-mono text-xs break-all text-fg">{target.label}</span>.
        </DialogDescription>
      </DialogHeader>
      <Field
        id={ids.pass}
        label="Your password"
        hint="Changing what the lists contain asks for your dashboard password again."
        error={passwordError ?? undefined}
      >
        <Input
          id={ids.pass}
          name="password"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-invalid={passwordError ? true : undefined}
          aria-describedby={passwordError ? `${ids.pass}-error` : `${ids.pass}-hint`}
        />
      </Field>
      <FormError id={ids.err} message={error} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Removing…" : "Remove"}
        </Button>
      </DialogFooter>
    </form>
  )
}

/** Lives only while open, so the typed password is dropped the moment it closes. */
export function RemoveOverrideDialog({
  target,
  onClose,
}: {
  target: RemovingOverride | null
  onClose: () => void
}) {
  return (
    <Dialog open={target !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="bg-popover">
        {target ? <RemoveForm target={target} onCancel={onClose} onDone={onClose} /> : null}
      </DialogContent>
    </Dialog>
  )
}
