import { useQueryClient } from "@tanstack/react-query"
import { useId, useState, type SyntheticEvent } from "react"
import { Field, FormError } from "@/components/form-parts"
import { SegmentedControl } from "@/components/segmented-control"
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
import {
  createInventory,
  describeDefendError,
  EXPOSURE_OPTIONS,
  updateInventory,
  validateInventory,
  type Exposure,
  type InventoryItem,
} from "@/lib/defend"
import { SENSORS, sensorMeta } from "@/lib/sensors"

function InventoryForm({
  item,
  preset,
  onDone,
  onCancel,
}: {
  item: InventoryItem | null
  /** A service to start from, when adding from the "attacked but not listed" section. */
  preset: string | null
  onDone: () => void
  onCancel: () => void
}) {
  const queryClient = useQueryClient()
  const [name, setName] = useState(item?.name ?? "")
  const [service, setService] = useState(item?.service ?? preset ?? "ssh")
  const [product, setProduct] = useState(item?.product ?? "")
  const [version, setVersion] = useState(item?.version ?? "")
  const [exposure, setExposure] = useState<Exposure>(item?.exposure ?? "internet")
  const [notes, setNotes] = useState(item?.notes ?? "")
  const [nameError, setNameError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const ids = {
    name: useId(),
    service: useId(),
    product: useId(),
    version: useId(),
    notes: useId(),
    err: useId(),
  }

  async function submit() {
    if (pending) return
    setError(null)
    const input = { name, service, product, version, exposure, notes }
    const found = validateInventory(input)
    setNameError(found.name ?? null)
    if (found.name) return
    setPending(true)
    try {
      if (item) await updateInventory(item.id, input)
      else await createInventory(input)
      await queryClient.invalidateQueries({ queryKey: ["defend"] })
      onDone()
    } catch (e) {
      setError(describeDefendError(e))
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
        <DialogTitle>{item ? "Edit this service" : "Add a service you run"}</DialogTitle>
        <DialogDescription>
          This list is only compared with what our own decoys recorded. Nothing is scanned and
          nothing is contacted.
        </DialogDescription>
      </DialogHeader>

      <Field id={ids.name} label="Name" error={nameError ?? undefined}>
        <Input
          id={ids.name}
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
          autoComplete="off"
          maxLength={80}
          placeholder="Jump host"
          aria-invalid={nameError ? true : undefined}
          aria-describedby={nameError ? `${ids.name}-error` : undefined}
        />
      </Field>

      <Field id={ids.service} label="Kind of service">
        <select
          id={ids.service}
          value={service}
          onChange={(e) => setService(e.target.value)}
          className="h-9 w-full rounded-md border border-input bg-bg px-3 text-base text-fg shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 md:text-sm"
        >
          {SENSORS.map((s) => (
            <option key={s} value={s}>
              {sensorMeta(s)?.label ?? s} · {sensorMeta(s)?.description ?? ""}
            </option>
          ))}
        </select>
      </Field>

      <div className="grid grid-cols-2 gap-3">
        <Field id={ids.product} label="Product (optional)">
          <Input
            id={ids.product}
            value={product}
            onChange={(e) => setProduct(e.target.value)}
            autoComplete="off"
            maxLength={80}
            placeholder="OpenSSH"
          />
        </Field>
        <Field id={ids.version} label="Version (optional)">
          <Input
            id={ids.version}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            autoComplete="off"
            maxLength={40}
            placeholder="9.6"
          />
        </Field>
      </div>

      <div className="flex flex-col gap-1.5">
        <span className="text-sm font-medium text-fg">Who can reach it</span>
        <SegmentedControl
          label="Who can reach it"
          value={exposure}
          onChange={setExposure}
          options={EXPOSURE_OPTIONS}
          className="self-start"
        />
      </div>

      <Field id={ids.notes} label="Notes (optional)">
        <Input
          id={ids.notes}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          autoComplete="off"
          maxLength={300}
        />
      </Field>

      <FormError id={ids.err} message={error} />

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? "Saving…" : item ? "Save changes" : "Add service"}
        </Button>
      </DialogFooter>
    </form>
  )
}

export function InventoryDialog({
  open,
  onOpenChange,
  item,
  preset = null,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  item: InventoryItem | null
  preset?: string | null
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-popover">
        <InventoryForm
          item={item}
          preset={preset}
          onCancel={() => onOpenChange(false)}
          onDone={() => onOpenChange(false)}
        />
      </DialogContent>
    </Dialog>
  )
}
