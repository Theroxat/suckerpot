import { keepPreviousData, useQuery } from "@tanstack/react-query"
import {
  Bug,
  Clock,
  Crosshair,
  Flag,
  Globe,
  Search,
  SearchX,
  ShieldAlert,
  type LucideIcon,
} from "lucide-react"
import { createContext, use, useCallback, useEffect, useMemo, useState } from "react"
import { useNavigate } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { ScannerBadge } from "@/components/scanner-badge"
import { formatNumber, maskIpsInText, plural } from "@/lib/format"
import {
  GROUP_LABEL,
  MIN_QUERY,
  cleanQuery,
  hitHref,
  loadRecent,
  orderedGroups,
  rememberSearch,
  searchApi,
  type SearchHit,
  type SearchKind,
} from "@/lib/search"
import { cn } from "@/lib/utils"

interface PaletteValue {
  open: boolean
  setOpen: (open: boolean) => void
}

const PaletteContext = createContext<PaletteValue>({ open: false, setOpen: () => undefined })

// eslint-disable-next-line react-refresh/only-export-components
export function useSearchPalette(): PaletteValue {
  return use(PaletteContext)
}

/** Short enough to fit a 390 px phone; the help text under it names every kind. */
const PLACEHOLDER = "Search addresses, CVEs, hashes, domains"

/** One example per kind; a click fills the box. Documentation addresses only. */
const EXAMPLES = ["203.0.113.", "CVE-2026-109618", "mirai"] as const

const KIND_ICON: Record<SearchKind, LucideIcon> = {
  ip: Crosshair,
  campaign: Flag,
  cve: ShieldAlert,
  hash: Bug,
  domain: Globe,
}

/** True on Apple platforms, where the shortcut is Cmd+K. */
// eslint-disable-next-line react-refresh/only-export-components
export function isApplePlatform(): boolean {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent)
}

/** Ctrl+K (Cmd+K on a Mac) opens the palette from anywhere; Escape closes it. */
function useShortcut(toggle: () => void) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault()
        toggle()
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [toggle])
}

export function SearchPaletteProvider({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  const toggle = useCallback(() => setOpen((o) => !o), [])
  useShortcut(toggle)
  const value = useMemo(() => ({ open, setOpen }), [open])
  return (
    <PaletteContext value={value}>
      {children}
      <SearchPalette open={open} onOpenChange={setOpen} />
    </PaletteContext>
  )
}

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return debounced
}

function Hit({ hit, masked, onSelect }: { hit: SearchHit; masked: boolean; onSelect: () => void }) {
  const Icon = KIND_ICON[hit.kind]
  const mono = hit.kind !== "campaign"
  const label = masked ? maskIpsInText(hit.label) : hit.label
  return (
    <CommandItem
      value={`${hit.kind}:${hit.value}`}
      onSelect={onSelect}
      className="min-h-11 gap-3 py-2 sm:min-h-10"
    >
      <Icon aria-hidden className="size-4 text-fg-subtle" strokeWidth={1.85} />
      <span className="min-w-0 flex-1">
        <span className={cn("block truncate text-sm text-fg", mono && "font-mono text-xs")}>
          {label}
        </span>
        {hit.detail ? (
          <span className="block truncate text-xs text-fg-muted">
            {masked ? maskIpsInText(hit.detail) : hit.detail}
          </span>
        ) : null}
      </span>
      {hit.benign ? <ScannerBadge short /> : null}
      {hit.count != null ? (
        <span className="text-xs text-fg-muted tabular-nums">
          {hit.kind === "ip" || hit.kind === "campaign"
            ? plural(hit.count, "session")
            : formatNumber(hit.count)}
        </span>
      ) : null}
    </CommandItem>
  )
}

function SearchPalette({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const navigate = useNavigate()
  const { masked } = useIpMask()
  const [input, setInput] = useState("")
  const q = useDebounced(cleanQuery(input), 200)
  const ready = q.length >= MIN_QUERY

  // Read each time the palette opens: a search made a moment ago must show up.
  const recent = useMemo(() => (open ? loadRecent() : []), [open])
  const close = (next: boolean) => {
    if (!next) setInput("")
    onOpenChange(next)
  }

  const result = useQuery({
    queryKey: ["search", q],
    queryFn: () => searchApi.search(q),
    enabled: open && ready,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })
  const groups = orderedGroups(ready ? result.data : undefined)
  const typing = cleanQuery(input) !== q
  const searching = ready && (result.isFetching || typing)

  const go = (hit: SearchHit) => {
    rememberSearch(q)
    close(false)
    void navigate(hitHref(hit))
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent
        showCloseButton={false}
        className="top-[4.5rem] translate-y-0 gap-0 overflow-hidden p-0 sm:top-[12vh] sm:max-w-xl"
      >
        <DialogTitle className="sr-only">Search</DialogTitle>
        <DialogDescription className="sr-only">
          Find an address, file hash, domain, CVE or campaign.
        </DialogDescription>
        <Command shouldFilter={false} label="Search" className="rounded-lg bg-popover">
          <CommandInput
            value={input}
            onValueChange={setInput}
            maxLength={128}
            placeholder={PLACEHOLDER}
            aria-label="Search"
          />
          <CommandList className="max-h-[min(24rem,60dvh)]">
            {!ready ? (
              <>
                {recent.length > 0 ? (
                  <CommandGroup heading="Recent searches">
                    {recent.map((r) => (
                      <CommandItem
                        key={r}
                        value={`recent:${r}`}
                        onSelect={() => setInput(r)}
                        className="min-h-11 gap-3 sm:min-h-10"
                      >
                        <Clock aria-hidden className="size-4 text-fg-subtle" />
                        <span className="font-mono text-xs">{masked ? maskIpsInText(r) : r}</span>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                ) : null}
                <div className="px-4 py-4">
                  <p className="text-sm text-fg-muted">
                    Type at least two characters: an address or its start, a CVE, a file hash, a
                    domain, or part of a campaign name.
                  </p>
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-fg-subtle">Try</span>
                    {EXAMPLES.map((ex) => (
                      <button
                        key={ex}
                        type="button"
                        onClick={() => setInput(ex)}
                        className="inline-flex h-7 items-center rounded-sm border px-2 font-mono text-2xs text-fg-muted transition-colors duration-150 hover:border-border-strong hover:text-fg"
                      >
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              </>
            ) : searching && groups.length === 0 ? (
              <p role="status" className="px-4 py-6 text-center text-sm text-fg-muted">
                Searching…
              </p>
            ) : (
              <>
                {groups.length === 0 ? (
                  <div role="status" className="px-6 py-8 text-center text-sm text-fg-muted">
                    <SearchX aria-hidden className="mx-auto mb-2 size-5 text-fg-subtle" />
                    Nothing matches &ldquo;{q}&rdquo;. Check the spelling, or paste the full address
                    or hash.
                  </div>
                ) : null}
                {groups.map((g) => (
                  <CommandGroup key={g.kind} heading={GROUP_LABEL[g.kind]}>
                    {g.hits.map((hit) => (
                      <Hit
                        key={`${hit.kind}:${hit.value}`}
                        hit={hit}
                        masked={masked}
                        onSelect={() => go(hit)}
                      />
                    ))}
                    {g.more ? (
                      <p className="px-2 py-1 text-xs text-fg-subtle">
                        More matches exist: type a little more to narrow them down.
                      </p>
                    ) : null}
                  </CommandGroup>
                ))}
              </>
            )}
          </CommandList>
          <div className="flex items-center justify-between border-t px-3 py-2 text-2xs text-fg-subtle">
            <span className="hidden sm:inline">
              <kbd className="font-sans">↑</kbd> <kbd className="font-sans">↓</kbd> to move,{" "}
              <kbd className="font-sans">Enter</kbd> to open
            </span>
            <span className="hidden sm:inline">
              <kbd className="font-sans">Esc</kbd> to close
            </span>
            <button
              type="button"
              onClick={() => close(false)}
              className="-my-1 inline-flex h-8 items-center rounded-md px-2 text-xs text-fg-muted hover:text-fg sm:hidden"
            >
              Close
            </button>
          </div>
        </Command>
      </DialogContent>
    </Dialog>
  )
}

/** The search box in the header: looks like an input, opens the palette. */
export function SearchTrigger({
  className,
  compact = false,
}: {
  className?: string
  /** Icon only (phones). */
  compact?: boolean
}) {
  const { setOpen } = useSearchPalette()
  const shortcut = isApplePlatform() ? "⌘K" : "Ctrl K"
  if (compact) {
    return (
      <button
        type="button"
        aria-label="Search"
        onClick={() => setOpen(true)}
        className={cn(
          "inline-flex size-10 items-center justify-center rounded-md text-fg-muted hover:bg-surface-hover hover:text-fg",
          className,
        )}
      >
        <Search aria-hidden className="size-5" />
      </button>
    )
  }
  return (
    <button
      type="button"
      onClick={() => setOpen(true)}
      aria-label="Search"
      aria-keyshortcuts="Control+K Meta+K"
      className={cn(
        "flex h-9 w-full items-center gap-2.5 rounded-md border bg-surface px-3 text-left text-sm text-fg-muted shadow-xs transition-colors duration-150 hover:border-border-strong hover:bg-surface-hover/60",
        className,
      )}
    >
      <Search aria-hidden className="size-4 shrink-0 text-fg-subtle" />
      <span className="min-w-0 flex-1 truncate">{PLACEHOLDER}</span>
      <kbd className="shrink-0 rounded-xs border px-1.5 font-sans text-2xs text-fg-subtle">
        {shortcut}
      </kbd>
    </button>
  )
}
