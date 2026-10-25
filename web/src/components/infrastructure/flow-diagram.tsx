import { useMemo, useState } from "react"
import { useNavigate } from "react-router"
import { useIpMask } from "@/app/ip-mask"
import { formatNumber, maskIp, plural } from "@/lib/format"
import {
  buildFlow,
  maskDefanged,
  type FlowNode,
  type InfrastructureGraph,
} from "@/lib/infrastructure"

const W = 900
const ROW = 30
const PAD = 14
const SRC_X = 170 // source dots; labels end just left of it
const PILL_X = 480 // centre of the indicator pills
const PILL_W = 250
const FAM_X = 782 // family dots; labels start just right of it

interface Placed<T> {
  node: T
  y: number
}

function place(nodes: readonly FlowNode[], height: number): Placed<FlowNode>[] {
  const used = nodes.length * ROW
  const top = PAD + Math.max(0, (height - 2 * PAD - used) / 2)
  return nodes.map((node, i) => ({ node, y: top + i * ROW + ROW / 2 }))
}

function curve(x1: number, y1: number, x2: number, y2: number): string {
  const mid = (x1 + x2) / 2
  return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`
}

const shorten = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s)

interface FlowDiagramProps {
  graph: InfrastructureGraph
  onOpenIndicator: (id: number) => void
}

/**
 * Source addresses on the left, the indicators they used in the middle, the malware families on
 * the right. Plain SVG: no graph library. Indicators are buttons that open the detail panel;
 * addresses open their profile. Nothing in it is a link to an indicator host.
 */
export function FlowDiagram({ graph, onOpenIndicator }: FlowDiagramProps) {
  const flow = useMemo(() => buildFlow(graph), [graph])
  const navigate = useNavigate()
  const { masked } = useIpMask()
  const [active, setActive] = useState<string | null>(null)

  const rows = Math.max(flow.sources.length, flow.indicators.length, flow.families.length, 1)
  const height = rows * ROW + 2 * PAD
  const src = place(flow.sources, height)
  const ind = place(flow.indicators, height)
  const fam = place(flow.families, height)
  const pos = new Map<string, { x: number; y: number }>()
  for (const { node, y } of src) pos.set(node.id, { x: SRC_X, y })
  for (const { node, y } of ind) pos.set(node.id, { x: PILL_X, y })
  for (const { node, y } of fam) pos.set(node.id, { x: FAM_X, y })

  const maxWeight = Math.max(1, ...flow.edges.map((e) => e.weight))
  const connected = new Set<string>()
  if (active) {
    connected.add(active)
    for (const e of flow.edges) {
      if (e.source === active) connected.add(e.target)
      if (e.target === active) connected.add(e.source)
    }
  }
  const edgeOn = (s: string, t: string) => active !== null && (s === active || t === active)

  const hiddenBits = [
    flow.hidden.indicators > 0 ? plural(flow.hidden.indicators, "more indicator") : null,
    flow.hidden.families > 0 ? plural(flow.hidden.families, "more family", "more families") : null,
  ].filter(Boolean)

  return (
    <figure className="m-0">
      <svg
        viewBox={`0 0 ${W} ${height}`}
        role="group"
        aria-label={`Flow from ${plural(flow.sources.length, "source")} through ${plural(flow.indicators.length, "indicator")} to ${plural(flow.families.length, "malware family", "malware families")}`}
        className="h-auto w-full"
        onMouseLeave={() => setActive(null)}
      >
        <g fill="none" aria-hidden>
          {flow.edges.map((e) => {
            const a = pos.get(e.source)
            const b = pos.get(e.target)
            if (!a || !b) return null
            const isFamily = e.target.startsWith("f:")
            const x1 = isFamily ? PILL_X + PILL_W / 2 : a.x + 5
            const x2 = isFamily ? b.x - 5 : PILL_X - PILL_W / 2
            const on = edgeOn(e.source, e.target)
            return (
              <path
                key={`${e.source}>${e.target}`}
                d={curve(x1, a.y, x2, b.y)}
                stroke={on ? "var(--fg-muted)" : "var(--border-strong)"}
                strokeOpacity={active && !on ? 0.25 : on ? 0.9 : 0.7}
                strokeWidth={0.8 + 2.4 * (e.weight / maxWeight)}
                style={{ transition: "stroke-opacity 150ms, stroke 150ms" }}
              />
            )
          })}
        </g>

        {src.map(({ node, y }) => (
          <SourceNode
            key={node.id}
            node={node}
            y={y}
            masked={masked}
            dim={active !== null && !connected.has(node.id)}
            onOpen={() => void navigate(`/attackers/${encodeURIComponent(node.label)}`)}
          />
        ))}

        {ind.map(({ node, y }) => {
          const label = masked ? maskDefanged(node.label) : node.label
          const known = node.known === true
          const dim = active !== null && !connected.has(node.id)
          return (
            <g
              key={node.id}
              role="button"
              tabIndex={0}
              aria-label={`${label}: ${plural(node.weight, "address", "addresses")}${known ? ", known malicious" : ""}. Open details`}
              onClick={() => node.indicator_id != null && onOpenIndicator(node.indicator_id)}
              onKeyDown={(ev) => {
                if ((ev.key === "Enter" || ev.key === " ") && node.indicator_id != null) {
                  ev.preventDefault()
                  onOpenIndicator(node.indicator_id)
                }
              }}
              onMouseEnter={() => setActive(node.id)}
              onFocus={() => setActive(node.id)}
              onBlur={() => setActive(null)}
              className="cursor-pointer outline-none [&:focus-visible>rect]:stroke-[var(--ring)] [&:focus-visible>rect]:stroke-2"
              opacity={dim ? 0.45 : 1}
              style={{ transition: "opacity 150ms" }}
            >
              <rect
                x={PILL_X - PILL_W / 2}
                y={y - 12}
                width={PILL_W}
                height={24}
                rx={6}
                fill="var(--surface-raised)"
                stroke={known ? "var(--sev-severe)" : "var(--border-strong)"}
                strokeOpacity={known ? 0.6 : 1}
              />
              {known ? (
                <polygon
                  points={`${PILL_X - PILL_W / 2 + 12},${y - 5} ${PILL_X - PILL_W / 2 + 18},${y} ${PILL_X - PILL_W / 2 + 12},${y + 5} ${PILL_X - PILL_W / 2 + 6},${y}`}
                  fill="var(--sev-severe)"
                />
              ) : (
                <circle
                  cx={PILL_X - PILL_W / 2 + 12}
                  cy={y}
                  r={3.5}
                  fill="none"
                  stroke="var(--fg-subtle)"
                  strokeWidth={1.5}
                />
              )}
              <text
                x={PILL_X - PILL_W / 2 + 26}
                y={y + 4}
                fontSize={11.5}
                fill="var(--fg)"
                fontFamily="var(--font-mono)"
              >
                {shorten(label, 30)}
              </text>
              <text
                x={PILL_X + PILL_W / 2 - 10}
                y={y + 4}
                fontSize={11}
                textAnchor="end"
                fill="var(--fg-muted)"
                style={{ fontVariantNumeric: "tabular-nums" }}
              >
                {formatNumber(node.weight)}
              </text>
            </g>
          )
        })}

        {fam.map(({ node, y }) => (
          <g
            key={node.id}
            role="link"
            tabIndex={0}
            aria-label={`Show indicators of family ${node.label}`}
            onClick={() =>
              void navigate(`/infrastructure?family=${encodeURIComponent(node.label)}`)
            }
            onKeyDown={(ev) => {
              if (ev.key === "Enter")
                void navigate(`/infrastructure?family=${encodeURIComponent(node.label)}`)
            }}
            className="cursor-pointer outline-none [&:focus-visible>text]:underline"
            opacity={active !== null && !connected.has(node.id) ? 0.45 : 1}
            style={{ transition: "opacity 150ms" }}
          >
            <circle cx={FAM_X} cy={y} r={4} fill="var(--fg-muted)" />
            <text x={FAM_X + 12} y={y + 4} fontSize={12} fill="var(--fg)">
              {shorten(node.label, 16)}
            </text>
          </g>
        ))}

        <g fontSize={10.5} fill="var(--fg-subtle)" fontWeight={500} letterSpacing="0.06em">
          <text x={SRC_X + 5} y={10} textAnchor="end">
            ADDRESSES
          </text>
          <text x={PILL_X} y={10} textAnchor="middle">
            INDICATORS · ADDRESSES USING THEM
          </text>
          <text x={FAM_X - 4} y={10}>
            MALWARE FAMILY
          </text>
        </g>
      </svg>
      <figcaption className="mt-3 text-xs text-fg-muted">
        Line width is the number of sessions. A diamond marks an indicator that threat intelligence
        knows as malicious.
        {flow.hidden.sources > 0
          ? ` ${plural(flow.hidden.sources, "address", "addresses")} are folded into one node.`
          : ""}
        {hiddenBits.length > 0
          ? ` Not shown: ${hiddenBits.join(" and ")}. The table lists everything.`
          : ""}
        {graph.truncated ? " The data itself was capped on the server." : ""}
      </figcaption>
    </figure>
  )
}

function SourceNode({
  node,
  y,
  masked,
  dim,
  onOpen,
}: {
  node: FlowNode
  y: number
  masked: boolean
  dim: boolean
  onOpen: () => void
}) {
  const folded = node.folded !== undefined
  const label = folded ? node.label : masked ? maskIp(node.label) : node.label
  return (
    <g
      opacity={dim ? 0.45 : 1}
      style={{ transition: "opacity 150ms" }}
      {...(folded
        ? {}
        : {
            role: "link",
            tabIndex: 0,
            "aria-label": `Show sessions from ${label}`,
            onClick: onOpen,
            onKeyDown: (ev: React.KeyboardEvent) => {
              if (ev.key === "Enter") onOpen()
            },
            className:
              "cursor-pointer outline-none [&:focus-visible>rect]:stroke-[var(--ring)] [&:focus-visible>rect]:stroke-2",
          })}
    >
      <rect x={0} y={y - 12} width={SRC_X + 12} height={24} fill="transparent" rx={4} />
      <circle
        cx={SRC_X}
        cy={y}
        r={folded ? 4 : 3.5}
        fill={folded ? "none" : "var(--fg-muted)"}
        stroke="var(--fg-muted)"
        strokeWidth={folded ? 1.5 : 0}
      />
      <text
        x={SRC_X - 12}
        y={y + 4}
        textAnchor="end"
        fontSize={11.5}
        fill={folded ? "var(--fg-muted)" : "var(--fg)"}
        fontFamily={folded ? undefined : "var(--font-mono)"}
      >
        {label}
      </text>
    </g>
  )
}
