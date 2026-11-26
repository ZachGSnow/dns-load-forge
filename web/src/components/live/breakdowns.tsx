import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { cn } from "@/lib/utils"
import {
  OUTCOME_DOT,
  OUTCOME_HINTS,
  OUTCOME_LABELS,
  OUTCOME_ORDER,
  OUTCOME_TONE,
  RECEIVED_RCODES,
  SENTINEL_RCODES,
} from "@/lib/constants"
import { fmtInt, fmtPct, num } from "@/lib/format"
import type { Snapshot } from "@/lib/schema"

const RCODE_FILL: Record<string, string> = {
  NOERROR: "bg-ok",
  NXDOMAIN: "bg-muted-foreground",
  REFUSED: "bg-bad",
  SERVFAIL: "bg-series-timeout",
  FORMERR: "bg-fn",
  NOTIMP: "bg-fn",
  TIMEOUT: "bg-warn",
  ERROR: "bg-fp",
}

function Bar({ share, fill }: { share: number; fill: string }) {
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
      <div
        className={cn("h-full rounded-full transition-[width]", fill)}
        style={{ width: `${Math.min(100, share * 100).toFixed(2)}%` }}
      />
    </div>
  )
}

/** Wire rcodes are a share of responses received; the sentinels a share of queries sent. */
export function RcodeCard({ snapshot }: { snapshot: Snapshot | null }) {
  const rcodes = snapshot?.rcodes ?? {}
  const sent = num(snapshot?.totals?.sent)
  const received = num(snapshot?.totals?.received)
  const total = [...RECEIVED_RCODES, ...SENTINEL_RCODES].reduce(
    (sum, key) => sum + num(rcodes[key]),
    0
  )

  const row = (name: string, base: number, sentinel: boolean) => {
    const count = num(rcodes[name])
    return (
      <div
        key={name}
        className="grid grid-cols-[5.5rem_1fr_4.5rem_3.5rem] items-center gap-3 text-xs"
      >
        <span
          className={cn(
            "font-mono",
            name === "NOERROR"
              ? "font-semibold text-foreground"
              : sentinel
                ? "text-warn"
                : "text-muted-foreground"
          )}
        >
          {name}
        </span>
        <Bar
          share={total > 0 ? count / total : 0}
          fill={RCODE_FILL[name] ?? "bg-primary"}
        />
        <span className="text-right font-mono num">{fmtInt(count)}</span>
        <span className="text-right font-mono text-muted-foreground num">
          {fmtPct(base > 0 ? (100 * count) / base : 0)}
        </span>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>RCODE breakdown</CardTitle>
        <CardDescription>
          of {fmtInt(sent)} sent, {fmtInt(received)} answered
          {sent > 0 ? ` (${fmtPct((100 * received) / sent)})` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2.5">
        {RECEIVED_RCODES.map((name) => row(name, received, false))}
        <Separator className="my-1 border-dashed" />
        {SENTINEL_RCODES.map((name) => row(name, sent, true))}
        <p className="pt-1 text-xs text-muted-foreground">
          Answer codes are a share of responses received; TIMEOUT and ERROR are
          a share of queries sent, since they never arrived.
        </p>
      </CardContent>
    </Card>
  )
}

export function OutcomesCard({ snapshot }: { snapshot: Snapshot | null }) {
  const outcomes = snapshot?.outcomes ?? {}
  const total = OUTCOME_ORDER.reduce((sum, key) => sum + num(outcomes[key]), 0)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Query outcomes</CardTitle>
        <CardDescription>
          {fmtInt(total)} completed queries, judged against each category's
          expectation
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div
          className="flex h-3 w-full overflow-hidden rounded-full bg-muted"
          aria-hidden
        >
          {OUTCOME_ORDER.map((key) => {
            const share = total > 0 ? num(outcomes[key]) / total : 0
            return share > 0 ? (
              <div
                key={key}
                className={OUTCOME_DOT[key]}
                style={{ width: `${(share * 100).toFixed(3)}%` }}
              />
            ) : null
          })}
        </div>
        <ul className="flex flex-col gap-2">
          {OUTCOME_ORDER.map((key) => {
            const value = num(outcomes[key])
            const alarming =
              (key === "false_positive" ||
                key === "false_negative" ||
                key === "timeout" ||
                key === "error") &&
              value > 0
            return (
              <li
                key={key}
                className="flex items-center gap-2 text-sm"
                title={OUTCOME_HINTS[key]}
              >
                <span
                  aria-hidden
                  className={cn("size-2 rounded-full", OUTCOME_DOT[key])}
                />
                <span className="flex-1 text-muted-foreground">
                  {OUTCOME_LABELS[key]}
                </span>
                <span
                  className={cn(
                    "font-mono num",
                    alarming
                      ? cn("font-semibold", OUTCOME_TONE[key])
                      : "text-foreground"
                  )}
                >
                  {fmtInt(value)}
                </span>
                <span className="w-14 text-right font-mono text-xs text-muted-foreground num">
                  {fmtPct(total > 0 ? (100 * value) / total : 0)}
                </span>
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
