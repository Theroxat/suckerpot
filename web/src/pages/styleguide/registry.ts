import type { ComponentType } from "react"

/**
 * What a feature adds to the styleguide: create `pages/styleguide/<feature>.tsx` that exports
 *
 *   export const section: FeatureSection = { id: "campaigns", label: "Campaigns", order: 10, Component }
 *
 * where `Component` renders a `<Section id=... title=... description=...>` from `./parts`. Files
 * are picked up by the glob below, so nobody edits a shared list and feature branches never
 * collide here.
 */
export interface FeatureSection {
  id: string
  label: string
  /** Lower comes first; ties sort by id. */
  order?: number
  Component: ComponentType
}

const modules = import.meta.glob<{ section?: FeatureSection }>("./*.tsx", { eager: true })

export const featureSections: FeatureSection[] = Object.values(modules)
  .flatMap((m) => (m.section ? [m.section] : []))
  .sort((a, b) => (a.order ?? 100) - (b.order ?? 100) || a.id.localeCompare(b.id))
