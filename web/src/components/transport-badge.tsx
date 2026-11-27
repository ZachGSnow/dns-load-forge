import { LockIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { TRANSPORT_HINT, TRANSPORT_LABEL } from "@/lib/transport"
import { cn } from "@/lib/utils"

/** DoT, DoH or TCP next to a target; nothing for plain DNS over UDP. */
export function TransportBadge({
  transport,
  className,
}: {
  transport?: string
  className?: string
}) {
  if (!transport || transport === "udp") return null
  const encrypted = transport === "tls" || transport === "https"
  return (
    <Badge
      variant="outline"
      title={TRANSPORT_HINT[transport]}
      className={cn("font-mono font-normal text-info", className)}
    >
      {encrypted ? <LockIcon data-icon="inline-start" /> : null}
      {TRANSPORT_LABEL[transport] ?? transport}
    </Badge>
  )
}
