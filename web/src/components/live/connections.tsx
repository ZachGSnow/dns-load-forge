import { TriangleAlertIcon } from "lucide-react"

import { TransportBadge } from "@/components/transport-badge"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { fmtInt, num } from "@/lib/format"
import type { Snapshot } from "@/lib/schema"
import { cn } from "@/lib/utils"

interface Cell {
  label: string
  value: number
  hint: string
  tone?: string
}

/** The connection pool of a TCP, DoT or DoH run.  UDP has none, so no card. */
export function ConnectionsCard({ snapshot }: { snapshot: Snapshot | null }) {
  const pool = snapshot?.connections
  if (!pool) return null
  const lost = num(pool.lost)
  const failed = num(pool.failed)
  const busy = num(pool.busy_drops)
  const cells: Cell[] = [
    {
      label: "Open now",
      value: num(pool.open),
      hint: "Connections open at this moment.",
    },
    {
      label: "Opened",
      value: num(pool.opened),
      hint: "Opened during the run, replacements included. Servers retire connections as a matter of course.",
    },
    {
      label: "Lost",
      value: lost,
      hint: "Closed with queries unanswered, or with an error.",
      tone: lost ? "text-warn" : undefined,
    },
    {
      label: "Could not open",
      value: failed,
      hint: "Connection attempts that failed; the reason is below.",
      tone: failed ? "text-bad" : undefined,
    },
    {
      label: "Re-sent",
      value: num(pool.retried),
      hint: "Queries sent again on another connection after the server closed theirs, as a resolver library would.",
    },
    {
      label: "Busy drops",
      value: busy,
      hint: "Queries dropped because every connection was busy: a limit of this machine's pool, not the server. Raise --connections.",
      tone: busy ? "text-warn" : undefined,
    },
  ]
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connections</CardTitle>
        <CardDescription>
          Opened before the first query, so no handshake is counted as latency.
        </CardDescription>
        <CardAction>
          <TransportBadge transport={snapshot?.run?.transport} />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 @lg/main:grid-cols-3 @2xl/main:grid-cols-6">
          {cells.map((cell) => (
            <div
              key={cell.label}
              className="flex flex-col gap-0.5"
              title={cell.hint}
            >
              <dt className="text-xs text-muted-foreground">{cell.label}</dt>
              <dd className={cn("font-mono text-lg num", cell.tone)}>
                {fmtInt(cell.value)}
              </dd>
            </div>
          ))}
        </dl>
        {pool.last_error ? (
          <p className="flex gap-2 text-sm text-warn">
            <TriangleAlertIcon className="mt-0.5 size-4 shrink-0" />
            <span>
              <span className="font-medium">Last problem: </span>
              {pool.last_error}
            </span>
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}
