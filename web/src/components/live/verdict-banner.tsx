import {
  CircleDashedIcon,
  GaugeIcon,
  HourglassIcon,
  OctagonXIcon,
  ShieldCheckIcon,
  ShieldOffIcon,
  TriangleAlertIcon,
} from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { cn } from "@/lib/utils"
import type { Snapshot, VerdictStatus } from "@/lib/schema"
import {
  DEFAULT_VERDICT_NOTES,
  VERDICT_TONE,
  verdictStatus,
} from "@/lib/snapshot"

const ICONS: Record<VerdictStatus, React.ElementType> = {
  filtering: ShieldCheckIcon,
  baseline: GaugeIcon,
  passthrough: ShieldOffIcon,
  degraded: TriangleAlertIcon,
  unknown: HourglassIcon,
  idle: CircleDashedIcon,
}

const HEADLINES: Record<VerdictStatus, string> = {
  filtering: "Filtering",
  baseline: "Baseline",
  passthrough: "Passthrough - policy is not being applied",
  degraded: "Degraded",
  unknown: "Not judged yet",
  idle: "Idle",
}

export function VerdictBanner({ snapshot }: { snapshot: Snapshot | null }) {
  const status = verdictStatus(snapshot)
  const tone = VERDICT_TONE[status] ?? VERDICT_TONE.unknown
  const Icon = ICONS[status] ?? HourglassIcon
  const note = snapshot?.verdict?.note || DEFAULT_VERDICT_NOTES[status]
  const failure = snapshot?.run?.state !== "running" ? snapshot?.run?.note : ""

  return (
    <div className="flex flex-col gap-3">
      <div
        role="status"
        aria-live="polite"
        className={cn(
          "flex items-start gap-4 rounded-xl border border-l-4 bg-card p-4 shadow-xs",
          tone.border,
          tone.tint
        )}
      >
        <div
          className={cn(
            "flex size-10 shrink-0 items-center justify-center rounded-lg bg-current/10",
            tone.text
          )}
        >
          <Icon className="size-5" />
        </div>
        <div className="flex min-w-0 flex-col gap-1">
          <p
            className={cn(
              "text-xs font-semibold tracking-widest uppercase",
              tone.text
            )}
          >
            Verdict
          </p>
          <p className="text-lg leading-tight font-semibold">
            {HEADLINES[status]}
          </p>
          <p className="text-sm text-muted-foreground">{note}</p>
        </div>
      </div>
      {failure && failure !== "stop requested" ? (
        <Alert variant="destructive">
          <OctagonXIcon />
          <AlertTitle>The last run stopped with an error</AlertTitle>
          <AlertDescription className="font-mono text-xs break-all">
            {failure}
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  )
}
