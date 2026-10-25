import { CircleAlert } from "lucide-react"
import { useId, useRef, useState, type ReactNode, type SyntheticEvent } from "react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import {
  describeKeyError,
  KEY_MESSAGES,
  KeyError,
  PROVIDER_NAMES,
  removeProviderKey,
  setProviderKey,
  validateKeyInput,
  type KeyField,
} from "@/lib/provider-keys"
import type { ProviderId } from "@/lib/settings"

function Field({
  id,
  label,
  hint,
  error,
  children,
}: {
  id: string
  label: string
  hint?: string
  error?: string | undefined
  children: ReactNode
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-fg">
        {label}
      </label>
      {children}
      {error ? (
        <p id={`${id}-error`} className="flex items-start gap-1.5 text-xs text-fg">
          <CircleAlert aria-hidden className="mt-0.5 size-3 shrink-0 text-fg-muted" />
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-xs text-fg-muted">
          {hint}
        </p>
      ) : null}
    </div>
  )
}

function FormError({ id, message }: { id: string; message: string | null }) {
  return (
    <div id={id} role="alert" aria-live="assertive" className="empty:hidden">
      {message ? (
        <p className="flex items-start gap-2 rounded-md border border-border-strong bg-surface-raised px-3 py-2 text-sm text-fg">
          <CircleAlert aria-hidden className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          {message}
        </p>
      ) : null}
    </div>
  )
}

interface FormProps {
  provider: ProviderId
  onDone: () => void
  onCancel: () => void
}

/**
 * Lives only while the dialog is open, so the typed key and password are dropped from memory
 * the moment it closes. Nothing is stored in the URL, in storage or in the query cache.
 */
function SetKeyForm({ provider, onDone, onCancel, replacing }: FormProps & { replacing: boolean }) {
  const name = PROVIDER_NAMES[provider]
  const [accountId, setAccountId] = useState("")
  const [key, setKey] = useState("")
  const [password, setPassword] = useState("")
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<KeyField, string>>>({})
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { account: useId(), key: useId(), pass: useId(), err: useId() }
  const passRef = useRef<HTMLInputElement>(null)

  async function submit() {
    if (pending) return
    const errors = validateKeyInput(provider, { key, accountId })
    setFieldErrors(errors)
    setFormError(null)
    setPasswordError(null)
    if (Object.keys(errors).length > 0) return
    if (!password) {
      setPasswordError("Enter your password to confirm.")
      passRef.current?.focus()
      return
    }
    setPending(true)
    try {
      await setProviderKey(provider, { key, accountId }, password)
      onDone()
    } catch (e) {
      setPassword("")
      if (e instanceof KeyError && e.reason === "wrong-password") {
        setPasswordError(KEY_MESSAGES["wrong-password"])
        passRef.current?.focus()
      } else if (e instanceof KeyError && e.reason === "invalid-key") {
        setFieldErrors({ key: describeKeyError(e) })
      } else {
        setFormError(describeKeyError(e))
      }
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
      autoComplete="off"
    >
      <DialogHeader className="text-left">
        <DialogTitle>
          {replacing ? "Replace" : "Set"} the {name} key
        </DialogTitle>
        <DialogDescription>
          The key is encrypted before it is stored and is never shown again, only its last four
          characters. {replacing ? "It replaces the current key." : null}
        </DialogDescription>
      </DialogHeader>

      {provider === "maxmind" ? (
        <Field
          id={ids.account}
          label="Account ID"
          hint="The number shown in your MaxMind account."
          error={fieldErrors.accountId}
        >
          <Input
            id={ids.account}
            name="maxmind-account-id"
            inputMode="numeric"
            autoComplete="off"
            autoFocus
            spellCheck={false}
            value={accountId}
            onChange={(e) => setAccountId(e.target.value.trim())}
            aria-invalid={fieldErrors.accountId ? true : undefined}
            aria-describedby={
              fieldErrors.accountId ? `${ids.account}-error` : `${ids.account}-hint`
            }
            className="font-mono"
          />
        </Field>
      ) : null}

      <Field
        id={ids.key}
        label={provider === "maxmind" ? "Licence key" : "API key"}
        error={fieldErrors.key}
      >
        <Input
          id={ids.key}
          name="provider-secret"
          type="password"
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          data-1p-ignore
          data-lpignore="true"
          autoFocus={provider !== "maxmind"}
          value={key}
          onChange={(e) => setKey(e.target.value.trim())}
          aria-invalid={fieldErrors.key ? true : undefined}
          aria-describedby={fieldErrors.key ? `${ids.key}-error` : undefined}
          className="font-mono"
        />
      </Field>

      <Field
        id={ids.pass}
        label="Your password"
        hint="Changing a key asks for your dashboard password again."
        error={passwordError ?? undefined}
      >
        <Input
          id={ids.pass}
          ref={passRef}
          name="password"
          type="password"
          autoComplete="current-password"
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
          {pending ? "Saving…" : "Save key"}
        </Button>
      </DialogFooter>
    </form>
  )
}

function RemoveKeyForm({ provider, onDone, onCancel }: FormProps) {
  const name = PROVIDER_NAMES[provider]
  const [password, setPassword] = useState("")
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = { pass: useId(), err: useId() }

  async function submit() {
    if (pending) return
    setPasswordError(null)
    setFormError(null)
    if (!password) {
      setPasswordError("Enter your password to confirm.")
      return
    }
    setPending(true)
    try {
      await removeProviderKey(provider, password)
      onDone()
    } catch (e) {
      setPassword("")
      if (e instanceof KeyError && e.reason === "wrong-password")
        setPasswordError(KEY_MESSAGES["wrong-password"])
      else setFormError(describeKeyError(e))
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
        <DialogTitle>Remove the {name} key</DialogTitle>
        <DialogDescription>
          The key stored in Settings is deleted. If <code className="font-mono">.env</code> also has
          a key for {name}, that one is used again.
        </DialogDescription>
      </DialogHeader>
      <Field
        id={ids.pass}
        label="Your password"
        hint="Changing a key asks for your dashboard password again."
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
          {pending ? "Removing…" : "Remove key"}
        </Button>
      </DialogFooter>
    </form>
  )
}

interface DialogProps {
  provider: ProviderId
  trigger: ReactNode
  onDone: () => void
}

export function SetKeyDialog({
  provider,
  trigger,
  onDone,
  replacing,
}: DialogProps & { replacing: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="bg-popover">
        <SetKeyForm
          provider={provider}
          replacing={replacing}
          onCancel={() => setOpen(false)}
          onDone={() => {
            setOpen(false)
            onDone()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}

export function RemoveKeyDialog({ provider, trigger, onDone }: DialogProps) {
  const [open, setOpen] = useState(false)
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="bg-popover">
        <RemoveKeyForm
          provider={provider}
          onCancel={() => setOpen(false)}
          onDone={() => {
            setOpen(false)
            onDone()
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
