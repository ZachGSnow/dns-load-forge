import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { cn } from "@/lib/utils"
import { clockOf, fmtMs, num } from "@/lib/format"
import type { Latency, SeriesPoint } from "@/lib/schema"

const config = {
  p95: { label: "p95 ms", color: "var(--series-p95)" },
} satisfies ChartConfig

function Stat({
  label,
  value,
  tone,
}: {
  label: string
  value: unknown
  tone?: string
}) {
  return (
    <div className="flex flex-col gap-0.5 rounded-lg border bg-muted/30 px-3 py-2">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={cn("font-mono text-lg font-semibold num", tone)}>
        {fmtMs(value)}
      </span>
    </div>
  )
}

export function LatencyCard({
  latency,
  series,
}: {
  latency: Latency
  series: SeriesPoint[]
}) {
  const p95 = num(latency.p95)
  const p99 = num(latency.p99)
  const data = series.map((point) => ({
    t: point.t,
    p95: Math.round(num(point.p95) * 10) / 10,
  }))
  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <CardTitle>Response latency</CardTitle>
        <CardDescription>
          Percentiles over the last 60 seconds, from histograms: each is the
          upper bound of its bucket, a mild over-estimate rather than a
          flattering one.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
          <Stat label="p50 ms" value={latency.p50} />
          <Stat
            label="p95 ms"
            value={p95}
            tone={p95 > 250 ? "text-bad" : p95 > 100 ? "text-warn" : "text-ok"}
          />
          <Stat
            label="p99 ms"
            value={p99}
            tone={p99 > 500 ? "text-bad" : p99 > 200 ? "text-warn" : undefined}
          />
          <Stat label="avg ms" value={latency.avg} />
          <Stat label="min ms" value={latency.min} />
          <Stat
            label="max ms"
            value={latency.max}
            tone={num(latency.max) > 1000 ? "text-warn" : undefined}
          />
        </div>
        <ChartContainer config={config} className="aspect-auto h-44 w-full">
          <AreaChart
            data={data}
            margin={{ left: 4, right: 4, top: 4, bottom: 0 }}
          >
            <defs>
              <linearGradient id="fill-p95" x1="0" y1="0" x2="0" y2="1">
                <stop
                  offset="5%"
                  stopColor="var(--color-p95)"
                  stopOpacity={0.35}
                />
                <stop
                  offset="95%"
                  stopColor="var(--color-p95)"
                  stopOpacity={0.02}
                />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="t"
              type="number"
              domain={["dataMin", "dataMax"]}
              tickFormatter={clockOf}
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              minTickGap={56}
              scale="time"
            />
            <YAxis
              tickLine={false}
              axisLine={false}
              width={44}
              tickFormatter={(v) => fmtMs(v)}
            />
            <ChartTooltip
              content={
                <ChartTooltipContent
                  indicator="line"
                  labelFormatter={(_, p) => clockOf(p?.[0]?.payload?.t)}
                />
              }
            />
            <Area
              dataKey="p95"
              type="monotone"
              stroke="var(--color-p95)"
              strokeWidth={2}
              fill="url(#fill-p95)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  )
}
