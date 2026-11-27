import {
  DownloadIcon,
  GitCompareArrowsIcon,
  Trash2Icon,
  TrophyIcon,
} from "lucide-react"
import * as React from "react"
import { Bar, BarChart, CartesianGrid, LabelList, XAxis, YAxis } from "recharts"
import { toast } from "sonner"

import { useRun } from "@/components/run-context"
import { VerdictBadge } from "@/components/status"
import { TransportBadge } from "@/components/transport-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { usePoll } from "@/hooks/use-poll"
import { cn } from "@/lib/utils"
import { DEMO, DOWNLOADS } from "@/lib/api"
import { CATEGORY_LABELS } from "@/lib/constants"
import { fmtFraction, fmtInt, fmtMs, fmtPct, fmtRate, num } from "@/lib/format"
import { clearHistory, fetchHistory } from "@/lib/resources"
import { dominantSignal } from "@/lib/signals"
import type { HistoryRun, Target } from "@/lib/schema"
import { endpointOf } from "@/lib/transport"

const PUBLIC_QPS_LIMIT = 100
const MIN_SECONDS = 10

function shortCategory(category: string): string {
  return (CATEGORY_LABELS[category] ?? category).replace(/^Block - /, "")
}

function TargetPick({
  target,
  checked,
  disabled,
  onChange,
}: {
  target: Target
  checked: boolean
  disabled: boolean
  onChange: (checked: boolean) => void
}) {
  const id = `pick-${target.name.replace(/[^A-Za-z0-9]/g, "-")}`
  const blocks = target.blocks ?? []
  return (
    <label
      htmlFor={id}
      className={cn(
        "flex cursor-pointer items-start gap-3 rounded-lg border bg-card p-3 transition-colors hover:bg-accent/50",
        checked && "border-primary/60 bg-primary/5",
        disabled && "cursor-not-allowed opacity-60"
      )}
    >
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onChange(value === true)}
        className="mt-0.5"
      />
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{target.name}</span>
          <Badge
            variant="outline"
            className="font-normal text-muted-foreground"
          >
            {target.kind === "public" ? "public resolver" : "appliance"}
          </Badge>
          <TransportBadge transport={target.transport} />
        </div>
        <span className="font-mono text-xs break-all text-muted-foreground">
          {endpointOf(target)}
        </span>
        <div className="flex flex-wrap gap-1">
          {blocks.length ? (
            blocks.map((category) => (
              <Badge key={category} variant="secondary" className="font-normal">
                {shortCategory(category)}
              </Badge>
            ))
          ) : (
            <Badge variant="secondary" className="font-normal">
              blocks nothing (baseline)
            </Badge>
          )}
        </div>
        {target.notes ? (
          <p className="line-clamp-2 text-xs text-muted-foreground">
            {target.notes}
          </p>
        ) : null}
      </div>
    </label>
  )
}

function ClearHistory({
  disabled,
  onCleared,
}: {
  disabled: boolean
  onCleared: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [busy, setBusy] = React.useState(false)
  const clear = async () => {
    setBusy(true)
    const result = await clearHistory()
    setBusy(false)
    setOpen(false)
    if (result.ok) {
      toast.success(result.message)
      onCleared()
    } else toast.error(result.message)
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={disabled}>
          <Trash2Icon />
          Clear
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Clear the run history?</DialogTitle>
          <DialogDescription>
            Every run in this table is forgotten, including the ones saved from
            earlier sessions. Export the JSON first to keep them.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button
            variant="destructive"
            disabled={busy}
            onClick={() => void clear()}
          >
            {busy ? <Spinner /> : <Trash2Icon />}
            Clear history
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

interface Best {
  block: number
  falseBlock: number
  p95: number
}

function bestOf(runs: HistoryRun[]): Best {
  let block = -1
  let falseBlock = Number.POSITIVE_INFINITY
  let p95 = Number.POSITIVE_INFINITY
  for (const run of runs) {
    if (typeof run.block_rate === "number" && run.block_rate > block)
      block = run.block_rate
    if (
      typeof run.false_block_rate === "number" &&
      run.false_block_rate < falseBlock
    )
      falseBlock = run.false_block_rate
    const value = num(run.latency_ms?.p95)
    if (value > 0 && value < p95) p95 = value
  }
  return { block, falseBlock, p95 }
}

const chartConfig = {
  block: { label: "Block rate %", color: "var(--series-recv)" },
  p95: { label: "p95 ms", color: "var(--series-p95)" },
} satisfies ChartConfig

function ResultCharts({ runs }: { runs: HistoryRun[] }) {
  const data = runs
    .slice()
    .reverse()
    .slice(0, 8)
    .map((run) => ({
      name: `${run.target} #${run.index}`,
      block:
        typeof run.block_rate === "number"
          ? Math.round(run.block_rate * 1000) / 10
          : 0,
      p95: Math.round(num(run.latency_ms?.p95) * 10) / 10,
    }))
  const height = Math.max(140, data.length * 36)
  const chart = (key: "block" | "p95", title: string, description: string) => (
    <div className="flex flex-col gap-2">
      <div>
        <p className="text-sm font-medium">{title}</p>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <ChartContainer
        config={chartConfig}
        className="aspect-auto w-full"
        style={{ height }}
      >
        <BarChart
          data={data}
          layout="vertical"
          margin={{ left: 0, right: 40, top: 0, bottom: 0 }}
        >
          <CartesianGrid horizontal={false} />
          <YAxis
            dataKey="name"
            type="category"
            tickLine={false}
            axisLine={false}
            width={150}
            tick={{ fontSize: 11 }}
          />
          <XAxis
            type="number"
            hide
            domain={key === "block" ? [0, 100] : [0, "auto"]}
          />
          <ChartTooltip
            cursor={false}
            content={<ChartTooltipContent hideLabel />}
          />
          <Bar
            dataKey={key}
            fill={`var(--color-${key})`}
            radius={4}
            isAnimationActive={false}
          >
            <LabelList
              dataKey={key}
              position="right"
              className="fill-foreground font-mono"
              fontSize={11}
              formatter={(v: unknown) =>
                key === "block" ? `${v}%` : `${v} ms`
              }
            />
          </Bar>
        </BarChart>
      </ChartContainer>
    </div>
  )
  return (
    <div className="grid gap-6 @3xl/main:grid-cols-2">
      {chart(
        "block",
        "Block rate",
        "Share of expected-block queries blocked. Higher is better."
      )}
      {chart("p95", "p95 latency", "Over the whole run. Lower is better.")}
    </div>
  )
}

export function ComparePage() {
  const run = useRun()
  const { data: history, refresh } = usePoll(fetchHistory, 4000)
  const [selected, setSelected] = React.useState<string[]>([])
  const [seconds, setSeconds] = React.useState("60")
  const runs = React.useMemo(
    () => (history?.runs ?? []).slice().reverse(),
    [history]
  )
  const best = bestOf(runs)
  const qps = Number.parseFloat(run.qps)
  const chosen = run.targets.filter((t) => selected.includes(t.name))
  const publicOverLimit =
    chosen.some((t) => t.kind === "public") &&
    Number.isFinite(qps) &&
    qps > PUBLIC_QPS_LIMIT
  const secondsValue = Number.parseFloat(seconds)
  const locked = run.running || DEMO

  const toggle = (name: string, checked: boolean) =>
    setSelected((current) =>
      checked
        ? [...current.filter((n) => n !== name), name]
        : current.filter((n) => n !== name)
    )

  const compare = async () => {
    // Keep the operator's tick order: that is the order the targets run in.
    const names = run.targets
      .map((t) => t.name)
      .filter((name) => selected.includes(name))
    const duration =
      Number.isFinite(secondsValue) && secondsValue >= MIN_SECONDS
        ? secondsValue
        : 60
    const result = await run.start({ targets: names, duration_s: duration })
    if (result.ok) void refresh()
  }

  const multiple = runs.length > 1
  return (
    <div className="flex flex-col gap-4 lg:gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Compare targets</CardTitle>
          <CardDescription>
            Tick two or more targets. They run one after another, never in
            parallel, on the same seed and the same traffic, so the generator
            and your NIC are not the thing being compared.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="grid gap-3 @lg/main:grid-cols-2 @4xl/main:grid-cols-3">
            {run.targets.map((target) => (
              <TargetPick
                key={target.name}
                target={target}
                checked={selected.includes(target.name)}
                disabled={locked}
                onChange={(checked) => toggle(target.name, checked)}
              />
            ))}
          </div>
          <div className="flex flex-wrap items-end gap-4">
            <Field className="w-40">
              <FieldLabel htmlFor="compare-seconds">Seconds each</FieldLabel>
              <Input
                id="compare-seconds"
                type="number"
                min={MIN_SECONDS}
                step={10}
                className="font-mono"
                value={seconds}
                disabled={locked}
                onChange={(event) => setSeconds(event.target.value)}
              />
            </Field>
            <Field className="w-auto">
              <FieldLabel>Rate</FieldLabel>
              <FieldDescription className="flex h-8 items-center gap-1">
                <span className="font-mono text-foreground num">
                  {fmtRate(qps)} qps
                </span>
                <span>(set on Live run)</span>
              </FieldDescription>
            </Field>
            <Button
              disabled={locked || run.busy || selected.length < 2}
              onClick={() => void compare()}
            >
              {run.busy ? <Spinner /> : <GitCompareArrowsIcon />}
              Run comparison
            </Button>
            <p
              className={cn(
                "text-sm text-muted-foreground",
                publicOverLimit && "text-warn"
              )}
            >
              {publicOverLimit
                ? `A public resolver is selected: the rate must be ${PUBLIC_QPS_LIMIT} qps or lower unless the server allows public targets.`
                : selected.length < 2
                  ? "Tick two or more targets."
                  : `${selected.length} targets, ${Number.isFinite(secondsValue) ? secondsValue : 60} seconds each.`}
            </p>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Results</CardTitle>
          <CardDescription>
            Every finished run lands here, comparison or not, and stays across
            restarts until you clear it. The best value in each column is
            highlighted.
          </CardDescription>
          <CardAction className="flex gap-2">
            <ClearHistory
              disabled={DEMO || !runs.length}
              onCleared={() => void refresh()}
            />
            <Button variant="outline" size="sm" asChild disabled={DEMO}>
              <a href={DEMO ? "#" : DOWNLOADS.history} download>
                <DownloadIcon />
                Export JSON
              </a>
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="flex flex-col gap-6 px-0">
          {runs.length ? (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="pl-4">Target</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead
                      className="text-right"
                      title="Share of expected-block queries that were blocked"
                    >
                      Blocked
                    </TableHead>
                    <TableHead
                      className="text-right"
                      title="Expected-block queries that resolved"
                    >
                      Leaked
                    </TableHead>
                    <TableHead title="How most blocks were signalled, and the Extended DNS Error the filter attached">
                      Blocks with
                    </TableHead>
                    <TableHead
                      className="text-right"
                      title="Share of expected-allow queries that were wrongly blocked"
                    >
                      False block
                    </TableHead>
                    <TableHead className="text-right">p50 ms</TableHead>
                    <TableHead className="text-right">p95 ms</TableHead>
                    <TableHead className="text-right">Loss</TableHead>
                    <TableHead className="pr-4 text-right">Sent</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.map((row) => {
                    const isBestBlock =
                      multiple &&
                      row.block_rate === best.block &&
                      best.block >= 0
                    const isBestFalse =
                      multiple && row.false_block_rate === best.falseBlock
                    const isBestP95 =
                      multiple && num(row.latency_ms?.p95) === best.p95
                    return (
                      <TableRow
                        key={`${row.index}-${row.finished_at}`}
                        title={row.note}
                      >
                        <TableCell className="pl-4">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{row.target}</span>
                            <TransportBadge transport={row.transport} />
                            <span className="font-mono text-xs text-muted-foreground">
                              #{row.index}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <VerdictBadge status={row.verdict} />
                        </TableCell>
                        <TableCell
                          className={cn(
                            "text-right font-mono num",
                            isBestBlock && "font-semibold text-ok"
                          )}
                        >
                          {isBestBlock ? (
                            <TrophyIcon className="mr-1 inline size-3.5" />
                          ) : null}
                          {fmtFraction(row.block_rate)}
                        </TableCell>
                        <TableCell
                          className={cn(
                            "text-right font-mono num",
                            num(row.leaked) > 0 && "text-warn"
                          )}
                        >
                          {fmtInt(row.leaked)}
                        </TableCell>
                        <TableCell className="text-xs">
                          <div>{dominantSignal(row.block_signals)}</div>
                          {row.ede?.length ? (
                            <div className="font-mono text-muted-foreground">
                              EDE {row.ede[0].code} {row.ede[0].name}
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell
                          className={cn(
                            "text-right font-mono num",
                            isBestFalse
                              ? "font-semibold text-ok"
                              : num(row.false_positives) > 0 && "text-warn"
                          )}
                        >
                          {fmtFraction(row.false_block_rate, 2)}
                        </TableCell>
                        <TableCell className="text-right font-mono num">
                          {fmtMs(row.latency_ms?.p50)}
                        </TableCell>
                        <TableCell
                          className={cn(
                            "text-right font-mono num",
                            isBestP95 && "font-semibold text-ok"
                          )}
                        >
                          {fmtMs(row.latency_ms?.p95)}
                        </TableCell>
                        <TableCell
                          className={cn(
                            "text-right font-mono num",
                            num(row.error_pct) > 1 && "text-warn"
                          )}
                        >
                          {fmtPct(row.error_pct)}
                        </TableCell>
                        <TableCell className="pr-4 text-right font-mono num">
                          {fmtInt(row.sent)}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
              <div className="px-4">
                <ResultCharts runs={runs} />
              </div>
            </>
          ) : (
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <GitCompareArrowsIcon />
                </EmptyMedia>
                <EmptyTitle>No finished runs yet</EmptyTitle>
                <EmptyDescription>
                  Every run you complete appears here, side by side.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
