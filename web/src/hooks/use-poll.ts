import { useCallback, useEffect, useRef, useState } from "react"

/**
 * Fetch something now and then every `intervalMs`.  `intervalMs` may change
 * between renders (the sources table polls quickly only while a list update
 * runs).  Returns the latest value and a function that re-fetches immediately.
 */
export function usePoll<T>(
  fetcher: () => Promise<T | null>,
  intervalMs: number,
  enabled = true
): { data: T | null; refresh: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null)
  const fetcherRef = useRef(fetcher)
  useEffect(() => {
    fetcherRef.current = fetcher
  }, [fetcher])

  const refresh = useCallback(async () => {
    const value = await fetcherRef.current()
    if (value !== null) setData(value)
  }, [])

  useEffect(() => {
    if (!enabled) return undefined
    void refresh()
    if (intervalMs <= 0) return undefined
    const timer = window.setInterval(() => void refresh(), intervalMs)
    return () => window.clearInterval(timer)
  }, [enabled, intervalMs, refresh])

  return { data, refresh }
}
