import { useEffect, useRef, useState } from "react"
import { useReducedMotion } from "./use-reduced-motion"

const easeOut = (t: number) => 1 - (1 - t) ** 3

/**
 * Smoothly animates towards `target` (ease-out, ~600 ms). The first value is
 * shown immediately; only changes are tweened. Honours reduced motion.
 */
export function useTweenedNumber(target: number, durationMs = 600): number {
  const reduced = useReducedMotion()
  const [value, setValue] = useState(target)
  const fromRef = useRef(target)
  const valueRef = useRef(target)

  useEffect(() => {
    valueRef.current = value
  }, [value])

  useEffect(() => {
    if (reduced || durationMs <= 0) return
    fromRef.current = valueRef.current
    if (fromRef.current === target) return
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / durationMs)
      setValue(fromRef.current + (target - fromRef.current) * easeOut(t))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, durationMs, reduced])

  return reduced || durationMs <= 0 ? target : value
}
