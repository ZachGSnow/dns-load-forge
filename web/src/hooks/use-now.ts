import { useSyncExternalStore } from "react"

/**
 * The time now, in seconds, re-rendering every `intervalMs` while mounted.  The
 * value is quantised to the interval, so it stays the same between ticks as
 * useSyncExternalStore requires, and render itself never reads the clock.
 */
export function useNow(intervalMs = 1000): number {
  return useSyncExternalStore(
    (onChange) => {
      const timer = window.setInterval(onChange, intervalMs)
      return () => window.clearInterval(timer)
    },
    () => (Math.floor(Date.now() / intervalMs) * intervalMs) / 1000
  )
}
