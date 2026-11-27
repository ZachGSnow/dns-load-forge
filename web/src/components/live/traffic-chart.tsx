import * as React from "react"
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  XAxis,
  YAxis,
} from "recharts"

import {
  Card,
  CardAction,
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
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { clockOf, fmtInt, fmtRate, num } from "@/lib/format"
import type { SeriesPoint } from "@/lib/schema"

const config = {
  sent: { label: "Sent", color: "var(--series-sent)" },
  recv: { label: "Received", color: "var(--series-recv)" },
  timeout: { label: "Timeout", color: "var(--series-timeout)" },
  fp: { label: "False positive", color: "var(--series-fp)" },
  fn: { label: "False negative", color: "var(--series-fn)" },
} satisfies ChartConfig

type Key = keyof typeof config

const LEGEND: {
  key: Key
  dashed?: boolean
  bar?: boolean
  emphasis?: string
}[] = [
  { key: "sent" },
  { key: "recv" },
  { key: "timeout", dashed: true },
  { key: "fp", bar: true, emphasis: "text-fp" },
  { key: "fn", bar: true, emphasis: "text-fn" },
]

const WINDOWS = { "60": 60, "300": 300 } as const

const axisTime = {
  dataKey: "t",
  type: "number" as const,
  domain: ["dataMin", "dataMax"] as [string, string],
  scale: "time" as const,
  tickFormatter: clockOf,
  tickLine: false,
  axisLine: false,
  minTickGap: 56,
}

function tooltip() {
  return (
    <ChartTooltip
      cursor={{ strokeDasharray: "3 3" }}
      content={
        <ChartTooltipContent
          indicator="line"
          labelFormatter={(_, payload) => clockOf(payload?.[0]?.payload?.t)}
        />
      }
    />
  )
}

export function TrafficChart({ series }: { series: SeriesPoint[] }) {
  const [windowKey, setWindowKey] = React.useState<keyof typeof WINDOWS>("300")
  // The newest bucket is the second still filling; drawn, it dips the line and
  // the legend shows a fraction of the real rate, so only finished seconds are shown.
  const data = React.useMemo(
    () => series.slice(0, -1).slice(-WINDOWS[windowKey]),
    [series, windowKey]
  )
  const latest = data.length ? data[data.length - 1] : null
  const anyFalse = data.some((point) => num(point.fp) > 0 || num(point.fn) > 0)

  return (
    <Card className="@2xl/main:col-span-2">
      <CardHeader>
        <CardTitle>Live traffic</CardTitle>
        <CardDescription>
          Queries per second, with false verdicts per second on their own scale
          underneath so the signal that matters is never flattened by the
          traffic.
        </CardDescription>
        <CardAction>
          <ToggleGroup
            type="single"
            variant="outline"
            size="sm"
            value={windowKey}
            onValueChange={(value) =>
              value && setWindowKey(value as keyof typeof WINDOWS)
            }
          >
            <ToggleGroupItem value="60">1 min</ToggleGroupItem>
            <ToggleGroupItem value="300">5 min</ToggleGroupItem>
          </ToggleGroup>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        <ChartContainer config={config} className="aspect-auto h-60 w-full">
          <LineChart
            data={data}
            syncId="traffic"
            margin={{ left: 4, right: 8, top: 8, bottom: 0 }}
          >
            <CartesianGrid vertical={false} />
            <XAxis {...axisTime} hide />
            <YAxis
              tickLine={false}
              axisLine={false}
              width={56}
              tickFormatter={(v) => fmtRate(v)}
              allowDecimals={false}
            />
            {tooltip()}
            <Line
              dataKey="sent"
              type="monotone"
              stroke="var(--color-sent)"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
            <Line
              dataKey="recv"
              type="monotone"
              stroke="var(--color-recv)"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
            <Line
              dataKey="timeout"
              type="monotone"
              stroke="var(--color-timeout)"
              strokeWidth={1.5}
              strokeDasharray="4 3"
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ChartContainer>
        <div className="relative">
          {!anyFalse && data.length ? (
            <p className="pointer-events-none absolute inset-x-0 top-6 z-10 text-center text-xs text-muted-foreground">
              No false positives or false negatives in this window
            </p>
          ) : null}
          <ChartContainer config={config} className="aspect-auto h-24 w-full">
            <BarChart
              data={data}
              syncId="traffic"
              margin={{ left: 4, right: 8, top: 4, bottom: 0 }}
              barCategoryGap={0}
            >
              <CartesianGrid vertical={false} />
              <XAxis {...axisTime} tickMargin={8} />
              <YAxis
                tickLine={false}
                axisLine={false}
                width={56}
                allowDecimals={false}
                tickCount={3}
              />
              {tooltip()}
              <Bar
                dataKey="fp"
                stackId="false"
                fill="var(--color-fp)"
                isAnimationActive={false}
              />
              <Bar
                dataKey="fn"
                stackId="false"
                fill="var(--color-fn)"
                isAnimationActive={false}
              />
            </BarChart>
          </ChartContainer>
        </div>
        <div className="flex flex-wrap gap-x-5 gap-y-2 pt-2 text-xs">
          {LEGEND.map(({ key, dashed, bar, emphasis }) => {
            const value = latest ? num(latest[key]) : 0
            return (
              <div
                key={key}
                className="flex items-center gap-2 text-muted-foreground"
              >
                <span
                  aria-hidden
                  className={
                    bar ? "size-2.5 rounded-[2px]" : "h-0.5 w-4 rounded-full"
                  }
                  style={{
                    background: dashed
                      ? `repeating-linear-gradient(90deg, ${config[key].color} 0 4px, transparent 4px 7px)`
                      : config[key].color,
                  }}
                />
                {config[key].label}
                <span
                  className={`font-mono font-medium num ${value > 0 && emphasis ? emphasis : "text-foreground"}`}
                >
                  {key === "sent" || key === "recv"
                    ? fmtRate(value)
                    : fmtInt(value)}
                </span>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
