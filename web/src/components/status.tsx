import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import type { Connection } from "@/lib/live"
import type { Expectation, RunState, VerdictStatus } from "@/lib/schema"
import { VERDICT_TONE } from "@/lib/snapshot"

function Dot({ className }: { className?: string }) {
  return (
    <span
      aria-hidden
      className={cn("size-1.5 rounded-full bg-current", className)}
    />
  )
}

const RUN_TONE: Record<string, string> = {
  running: "text-ok border-ok/40 bg-ok/10",
  starting: "text-warn border-warn/40 bg-warn/10",
  stopping: "text-warn border-warn/40 bg-warn/10",
  stopped: "text-muted-foreground",
  idle: "text-muted-foreground",
}

export function RunStateBadge({ state }: { state?: RunState | string }) {
  const value = state || "idle"
  return (
    <Badge
      variant="outline"
      className={cn("gap-1.5 capitalize", RUN_TONE[value])}
    >
      <Dot className={value === "running" ? "animate-pulse" : undefined} />
      {value}
    </Badge>
  )
}

const CONNECTION_LABEL: Record<Connection, string> = {
  connecting: "connecting",
  live: "live",
  polling: "polling",
  reconnecting: "reconnecting",
  demo: "demo data",
}

const CONNECTION_TONE: Record<Connection, string> = {
  connecting: "text-muted-foreground",
  live: "text-ok",
  polling: "text-warn",
  reconnecting: "text-bad",
  demo: "text-warn",
}

export function ConnectionBadge({ connection }: { connection: Connection }) {
  return (
    <Badge
      variant="outline"
      className={cn("gap-1.5", CONNECTION_TONE[connection])}
      title={
        connection === "polling"
          ? "The live stream is unavailable, so the page is polling once a second."
          : undefined
      }
    >
      <Dot />
      {CONNECTION_LABEL[connection]}
    </Badge>
  )
}

export function VerdictBadge({ status }: { status?: VerdictStatus | string }) {
  const key = (
    status && status in VERDICT_TONE ? status : "unknown"
  ) as VerdictStatus
  const tone = VERDICT_TONE[key]
  return (
    <Badge
      variant="outline"
      className={cn("font-mono tracking-wide uppercase", tone.text)}
    >
      {tone.label}
    </Badge>
  )
}

export function categoryTone(category?: string): string {
  const c = String(category ?? "")
  if (c === "enterprise") return "text-info border-info/40 bg-info/10"
  if (c.startsWith("allow")) return "text-ok border-ok/40 bg-ok/10"
  if (c === "borderline") return "text-warn border-warn/40 bg-warn/10"
  if (c.startsWith("block")) return "text-bad border-bad/40 bg-bad/10"
  return "text-muted-foreground"
}

export function CategoryBadge({ category }: { category?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("font-mono font-normal", categoryTone(category))}
    >
      {category || "-"}
    </Badge>
  )
}

const EXPECT_TONE: Record<Expectation, string> = {
  allow: "text-ok",
  block: "text-bad",
  unknown: "text-warn",
  nxdomain: "text-muted-foreground",
}

export function ExpectBadge({ expect }: { expect: Expectation }) {
  return (
    <Badge
      variant="outline"
      className={cn("font-mono font-normal", EXPECT_TONE[expect])}
    >
      {expect}
    </Badge>
  )
}
