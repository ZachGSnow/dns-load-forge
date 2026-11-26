import * as React from "react"

const MOBILE_BREAKPOINT = 768
const QUERY = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`

function subscribe(onChange: () => void) {
  const query = window.matchMedia(QUERY)
  query.addEventListener("change", onChange)
  return () => query.removeEventListener("change", onChange)
}

const isMobile = () => window.matchMedia(QUERY).matches

export function useIsMobile() {
  return React.useSyncExternalStore(subscribe, isMobile, () => false)
}
