import { useQueryClient } from "@tanstack/react-query"
import { useId, useRef, useState, type SyntheticEvent } from "react"
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
import { Textarea } from "@/components/ui/textarea"
import { abuseKeys } from "@/lib/abuse"
import { describeRepliesError, repliesApi } from "@/lib/replies"

const MAX_BYTES = 256 * 1024

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Public id of the report the reply belongs to, when known. */
  report?: string
}

/** "Add a reply": paste the whole message with its headers, or pick an .eml file. Text only. */
export function ReplyImportDialog({ open, onOpenChange, report }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        {open ? <ImportForm onOpenChange={onOpenChange} report={report} /> : null}
      </DialogContent>
    </Dialog>
  )
}

function ImportForm({ onOpenChange, report }: Omit<Props, "open">) {
  const id = useId()
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [raw, setRaw] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function pick(file: File | undefined) {
    if (!file) return
    if (file.size > MAX_BYTES) {
      setError("That file is too large (256 KiB at most).")
      return
    }
    setError(null)
    setRaw(await file.text())
  }

  async function submit() {
    if (!raw.trim()) {
      setError("Paste the message or pick an .eml file first.")
      return
    }
    if (new Blob([raw]).size > MAX_BYTES) {
      setError("That message is too large (256 KiB at most).")
      return
    }
    setPending(true)
    setError(null)
    try {
      const { id: importId } = await repliesApi.importReply(raw, report)
      // The worker parses it within a moment; wait for the verdict, but not for ever.
      for (let i = 0; i < 15; i++) {
        const s = await repliesApi.importState(importId)
        if (s.status === "failed") {
          setError(
            s.error_code === "not_a_message"
              ? "That does not look like an email message."
              : "The message could not be read.",
          )
          return
        }
        if (s.status === "done") break
        await new Promise((r) => setTimeout(r, 800))
      }
      void qc.invalidateQueries({ queryKey: abuseKeys.all })
      onOpenChange(false)
    } catch (e) {
      setError(describeRepliesError(e))
    } finally {
      setPending(false)
    }
  }

  return (
    <form
      noValidate
      className="flex flex-col gap-4"
      onSubmit={(e: SyntheticEvent) => {
        e.preventDefault()
        void submit()
      }}
    >
      <DialogHeader className="text-left">
        <DialogTitle>Add a reply</DialogTitle>
        <DialogDescription>
          Paste the whole message with its headers, or pick an .eml file. It is read as text and
          never opened. Nothing is sent.
        </DialogDescription>
      </DialogHeader>
      <Field id={id} label="Message" hint="256 KiB at most.">
        <Textarea
          id={id}
          rows={9}
          value={raw}
          spellCheck={false}
          autoComplete="off"
          className="font-mono text-xs"
          placeholder={"From: abuse@example.net\nSubject: Re: ...\n\nBody"}
          onChange={(e) => setRaw(e.target.value)}
        />
      </Field>
      <div>
        <input
          ref={fileRef}
          type="file"
          accept=".eml,message/rfc822"
          className="sr-only"
          aria-label="Pick an .eml file"
          onChange={(e) => void pick(e.target.files?.[0])}
        />
        <Button type="button" variant="outline" size="sm" onClick={() => fileRef.current?.click()}>
          Pick an .eml file
        </Button>
      </div>
      <FormError id={`${id}-err`} message={error} />
      <DialogFooter>
        <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Reading…" : "Add the reply"}
        </Button>
      </DialogFooter>
    </form>
  )
}
