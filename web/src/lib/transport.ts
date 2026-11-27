import { num } from "@/lib/format"
import type { Target } from "@/lib/schema"

/** Short names for how queries travel; mirrors TRANSPORT_LABELS in spec.py. */
export const TRANSPORT_LABEL: Record<string, string> = {
  udp: "UDP",
  tcp: "TCP",
  tls: "DoT",
  https: "DoH",
  http: "DoH",
}

export const TRANSPORT_HINT: Record<string, string> = {
  tcp: "DNS over TCP",
  tls: "DNS over TLS (RFC 7858)",
  https: "DNS over HTTPS (RFC 8484)",
  http: "DNS over HTTPS without TLS, for rehearsing on this machine",
}

/** Where a target's traffic goes.  Plain DNS keeps the short form (no :53). */
export function endpointOf(target: Target | undefined): string {
  if (!target) return ""
  const transport = target.transport ?? "udp"
  if (transport !== "udp" && target.endpoint) return target.endpoint
  const port = num(target.port, 53)
  return `${target.server}${port !== 53 ? `:${port}` : ""}`
}
