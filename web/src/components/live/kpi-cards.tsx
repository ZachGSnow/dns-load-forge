import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"
import {
  fmtBytes,
  fmtFraction,
  fmtInt,
  fmtMs,
  fmtPct,
  fmtRate,
  num,
} from "@/lib/format"
import type { Snapshot } from "@/lib/schema"
import { headline } from "@/lib/snapshot"

interface Kpi {
  label: string
  value: string
  tone?: string
  badge?: { text: string; tone?: string }
  footer: string
  hint?: string
}

function KpiCard({ kpi }: { kpi: Kpi }) {
  return (
    <Card className="@container/card gap-2" title={kpi.hint}>
      <CardHeader>
        <CardDescription>{kpi.label}</CardDescription>
        <CardTitle
          className={cn(
            "text-2xl font-semibold num @[250px]/card:text-3xl",
            kpi.tone
          )}
        >
          {kpi.value}
        </CardTitle>
        {kpi.badge ? (
          <CardAction>
            <Badge variant="outline" className={cn("num", kpi.badge.tone)}>
              {kpi.badge.text}
            </Badge>
          </CardAction>
        ) : null}
      </CardHeader>
      <CardFooter className="border-t-0 bg-transparent pb-4 text-xs text-muted-foreground">
        {kpi.footer}
      </CardFooter>
    </Card>
  )
}

export function KpiCards({ snapshot }: { snapshot: Snapshot | null }) {
  const rates = snapshot?.rates ?? {}
  const totals = snapshot?.totals ?? {}
  const latency = snapshot?.latency_ms ?? {}
  const run = snapshot?.run ?? {}
  const outcomes = snapshot?.outcomes ?? {}
  const lead = headline(snapshot)

  const targetQps = num(run.target_qps)
  const achieved = num(rates.qps_sent_avg)
  // Judged on the whole run: bursty arrivals swing a 5-second average by about
  // 5% either way, which would flicker a healthy generator into a warning.
  const elapsed = num(run.elapsed_s)
  const runAverage = elapsed >= 5 ? num(totals.sent) / elapsed : 0
  const ofTarget = targetQps > 0 ? (100 * runAverage) / targetQps : 0
  const loss = num(rates.error_pct)
  const p95 = num(latency.p95)
  const fp = num(outcomes.false_positive)
  const dropped = num(rates.dropped_pct)

  const kpis: Kpi[] = [
    {
      label: "Sent qps",
      value: fmtRate(rates.qps_sent),
      badge:
        targetQps > 0 && runAverage > 0
          ? {
              text: `${ofTarget.toFixed(0)}% of target`,
              tone: ofTarget < 90 ? "text-warn" : undefined,
            }
          : undefined,
      footer: `target ${fmtRate(targetQps)} qps, 5s avg ${fmtRate(achieved)}, run avg ${fmtRate(runAverage)}`,
      hint: "The badge compares the whole run's average with the target.",
    },
    {
      label: "Received qps",
      value: fmtRate(rates.qps_recv),
      footer: `${fmtInt(totals.received)} answered of ${fmtInt(totals.sent)} sent`,
    },
    {
      label: "Loss",
      value: fmtPct(loss),
      tone: loss >= 5 ? "text-bad" : loss > 0.5 ? "text-warn" : "text-ok",
      badge:
        dropped >= 1
          ? { text: `${dropped.toFixed(0)}% dropped`, tone: "text-warn" }
          : undefined,
      footer: `${fmtInt(totals.timeouts)} timeouts, window ${fmtPct(rates.window_error_pct)}`,
      hint: "Queries never answered, as a share of queries sent. 'dropped' is traffic the generator itself could not offer.",
    },
    {
      label: "p95 latency",
      value: `${fmtMs(p95)} ms`,
      tone: p95 > 250 ? "text-bad" : p95 > 100 ? "text-warn" : undefined,
      footer: `p50 ${fmtMs(latency.p50)} ms, p99 ${fmtMs(latency.p99)} ms (60s window)`,
    },
    {
      label: "Block rate",
      value: fmtFraction(lead.blockRate),
      tone:
        lead.blockRate === null
          ? "text-muted-foreground"
          : lead.blockRate < 0.2
            ? "text-bad"
            : lead.blockRate < 0.95
              ? "text-warn"
              : "text-ok",
      footer:
        lead.blockRate === null
          ? "nothing expected to be blocked"
          : `${fmtInt(lead.leaked)} leaked of ${fmtInt(lead.blocked + lead.leaked)}`,
      hint: "Share of expected-block queries that were blocked.",
    },
    {
      label: "False blocks",
      value: fmtInt(fp),
      tone: fp > 0 ? "text-fp" : "text-ok",
      badge:
        lead.falseBlockRate !== null && fp > 0
          ? { text: fmtFraction(lead.falseBlockRate, 2), tone: "text-fp" }
          : undefined,
      footer:
        fp > 0
          ? "allow-listed names blocked: see the table below"
          : `${fmtBytes(totals.bytes_sent)} out, ${fmtBytes(totals.bytes_received)} in`,
      hint: "Allow-listed queries refused, NXDOMAINed, sinkholed or dropped. This is what users report as outages.",
    },
  ]

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
      {kpis.map((kpi) => (
        <KpiCard key={kpi.label} kpi={kpi} />
      ))}
    </div>
  )
}
