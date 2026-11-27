import { useEffect, useState } from "react"

export const ROUTES = [
  "live",
  "compare",
  "capacity",
  "checks",
  "lists",
] as const
export type Route = (typeof ROUTES)[number]

function parse(hash: string): Route {
  const name = hash.replace(/^#\/?/, "").split(/[/?]/)[0]
  return (ROUTES as readonly string[]).includes(name) ? (name as Route) : "live"
}

/** Hash routing: no router dependency, and it works from any path or proxy. */
export function useRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState<Route>(() => parse(window.location.hash))
  useEffect(() => {
    const onChange = () => setRoute(parse(window.location.hash))
    window.addEventListener("hashchange", onChange)
    return () => window.removeEventListener("hashchange", onChange)
  }, [])
  const navigate = (next: Route) => {
    window.location.hash = `/${next}`
  }
  return [route, navigate]
}
