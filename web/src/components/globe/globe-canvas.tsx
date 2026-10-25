import { useEffect, useRef } from "react"
import type { LiveEvent } from "@/lib/api"
import type { Source } from "@/components/map/activity"
import { GlobeController } from "./globe-controller"
import type { GeoPoint } from "./geo"

interface GlobeCanvasProps {
  /** Newest first, already filtered by the page. */
  events: readonly LiveEvent[]
  /** Recent sources, aggregated per country (the persistent arcs). */
  sources: readonly Source[]
  now: number
  home: GeoPoint
  /** Stop adding comets (the feed is paused). */
  paused: boolean
  onUnavailable: () => void
}

/** The 3D globe. Imported lazily: it pulls in three.js. */
export default function GlobeCanvas({
  events,
  sources,
  now,
  home,
  paused,
  onUnavailable,
}: GlobeCanvasProps) {
  const hostRef = useRef<HTMLDivElement>(null)
  const controllerRef = useRef<GlobeController | null>(null)
  const latest = useRef({ events, sources, now, home, paused })

  useEffect(() => {
    latest.current = { events, sources, now, home, paused }
    controllerRef.current?.setHome(home)
    controllerRef.current?.feed(events, paused)
  }, [events, sources, now, home, paused])

  useEffect(() => {
    controllerRef.current?.setSources(sources, now)
  }, [sources, now])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return
    let controller: GlobeController
    try {
      controller = new GlobeController(host, latest.current.home)
    } catch {
      onUnavailable()
      return
    }
    controllerRef.current = controller
    controller.feed(latest.current.events, latest.current.paused)
    controller.setSources(latest.current.sources, latest.current.now)
    return () => {
      controllerRef.current = null
      controller.destroy()
      host.replaceChildren()
    }
  }, [onUnavailable])

  return <div ref={hostRef} className="absolute inset-0 [&_canvas]:outline-none" />
}
