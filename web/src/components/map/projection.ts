/**
 * Equal Earth projection (Šavrič, Patterson, Jenny 2018): equal-area, calm
 * proportions, no polar blow-up. Maps [lat, lon] in degrees to map units on a
 * MAP_WIDTH-wide plane, origin top-left, y down. scripts/gen-map-data.mjs uses
 * the same formula to pre-project the land and border paths.
 */
const A1 = 1.340264
const A2 = -0.081106
const A3 = 0.000893
const A4 = 0.003796
const M = Math.sqrt(3) / 2
/** x of the projection at lon 180, lat 0, in radians-units. */
const X_MAX = 2.7066297319215575
/** y of the projection at lat 90. */
const Y_MAX = 1.3173627591574133

export const MAP_WIDTH = 1000
const S = MAP_WIDTH / (2 * X_MAX)
export const MAP_HEIGHT = 2 * Y_MAX * S

export function project(lat: number, lon: number): [number, number] {
  const phi = (lat * Math.PI) / 180
  const lambda = (lon * Math.PI) / 180
  const t = Math.asin(M * Math.sin(phi))
  const t2 = t * t
  const t6 = t2 * t2 * t2
  const x = (lambda * Math.cos(t)) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
  const y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
  return [MAP_WIDTH / 2 + x * S, MAP_HEIGHT / 2 - y * S]
}
