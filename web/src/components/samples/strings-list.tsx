import { useVirtualizer } from "@tanstack/react-virtual"
import { useRef } from "react"

/** Printable strings found in the file: a virtualised, scrollable list of plain text. */
export function StringsList({ strings }: { strings: readonly string[] }) {
  const ref = useRef<HTMLDivElement>(null)
  // The virtualizer is used as intended; the compiler just cannot memoize its return value.
  // eslint-disable-next-line react-hooks/incompatible-library
  const v = useVirtualizer({
    count: strings.length,
    getScrollElement: () => ref.current,
    estimateSize: () => 24,
    overscan: 12,
  })
  return (
    <div
      ref={ref}
      tabIndex={0}
      role="list"
      aria-label="Strings found in the file"
      className="max-h-80 overflow-auto rounded-md border bg-bg focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="relative w-full" style={{ height: v.getTotalSize() }}>
        {v.getVirtualItems().map((item) => (
          <div
            key={item.key}
            role="listitem"
            className="absolute top-0 left-0 flex h-6 w-full items-center gap-3 px-3 font-mono text-xs"
            style={{ transform: `translateY(${item.start}px)` }}
          >
            <span aria-hidden className="w-8 shrink-0 text-right text-fg-subtle tabular-nums">
              {item.index + 1}
            </span>
            <span className="truncate text-fg" title={strings[item.index]}>
              {strings[item.index]}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
