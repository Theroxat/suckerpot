import { useId, useState, type ReactNode, type SyntheticEvent } from "react"
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
import { describeUserError, UserError } from "@/lib/users"

interface FormProps {
  title: string
  description: ReactNode
  confirmLabel: string
  pendingLabel: string
  /** Extra fields above the password (a role picker, say). */
  children?: ReactNode
  /** Runs the change with the administrator's password; resolves when it went through. */
  run: (password: string) => Promise<void>
  /** Checks the extra fields first; a message stops the submit. */
  validate?: () => string | null
  onDone: () => void
  onCancel: () => void
}

/**
 * Every change to a user asks for the administrator's own password again. Lives only while the
 * dialog is open, so the typed password is dropped the moment it closes.
 */
function ActionForm({
  title,
  description,
  confirmLabel,
  pendingLabel,
  children,
  run,
  validate,
  onDone,
  onCancel,
}: FormProps) {
  const [password, setPassword] = useState("")
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { pass: useId(), err: useId() }

  async function submit() {
    if (pending) return
    setPasswordError(null)
    setFormError(null)
    const problem = validate?.()
    if (problem) {
      setFormError(problem)
      return
    }
    if (!password) {
      setPasswordError("Enter your password to confirm.")
      return
    }
    setPending(true)
    try {
      await run(password)
      onDone()
    } catch (e) {
      setPassword("")
      if (e instanceof UserError && e.reason === "wrong-password")
        setPasswordError(describeUserError(e))
      else setFormError(describeUserError(e))
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
        <DialogTitle>{title}</DialogTitle>
        <DialogDescription>{description}</DialogDescription>
      </DialogHeader>
      {children}
      <Field
        id={ids.pass}
        label="Your password"
        hint="Changing users asks for your own dashboard password again."
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
      <FormError id={ids.err} message={formError} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? pendingLabel : confirmLabel}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function AdminActionDialog({
  open,
  onOpenChange,
  onDone,
  ...form
}: Omit<FormProps, "onCancel" | "onDone"> & {
  open: boolean
  onOpenChange: (open: boolean) => void
  onDone: () => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover">
        <ActionForm
          {...form}
          onCancel={() => onOpenChange(false)}
          onDone={() => {
            onOpenChange(false)
            onDone()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
