import { DownloadIcon, GaugeIcon, PlayIcon } from "lucide-react"
import * as React from "react"
import {
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  XAxis,
  YAxis,
} from "recharts"
import { toast } from "sonner"

import { useRun } from "@/components/run-context"
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
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Spinner } from "@/components/ui/spinner"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useNow } from "@/hooks/use-now"
import { usePoll } from "@/hooks/use-poll"
import { DEMO, DOWNLOADS } from "@/lib/api"
import { estimateSeconds, ramp } from "@/lib/capacity"
import { fmtDateTime, fmtInt, fmtPct, fmtRate, num } from "@/lib/format"
import { useLive } from "@/lib/live"
import { fetchCapacity, startCapacity } from "@/lib/resources"
import type {
  CapacityPayload,
  CapacitySlo,
  CapacityStatus,
  CapacityStep,
} from "@/lib/schema"
import { endpointOf } from "@/lib/transport"
import { cn } from "@/lib/utils"

/** Above this rate a public resolver needs --allow-public-target (targets.py). */
const PUBLIC_QPS_LIMIT = 100

const STATUS_LABEL: Record<CapacityStatus, string> = {
  pass: "Pass",
  fail: "Fail",
  generator: "Limit",
  small: "Too few",
  stopped: "Stopped",
}

const STATUS_TONE: Record<CapacityStatus, string> = {
  pass: "text-ok border-ok/40 bg-ok/10",
  fail: "text-bad border-bad/40 bg-bad/10",
  generator: "text-warn border-warn/40 bg-warn/10",
  small: "text-muted-foreground",
  stopped: "text-muted-foreground",
}

const STATUS_FILL: Record<CapacityStatus, string> = {
  pass: "var(--ok)",
  fail: "var(--bad)",
  generator: "var(--warn)",
  small: "var(--muted-foreground)",
  stopped: "var(--muted-foreground)",
}

const LIMIT_TEXT: Record<string, string> = {
  target: "the next step up broke a limit",
  max: "every rate tried passed",
  start: "the first rate already broke a limit",
  generator: "this machine could not send more",
  stopped: "stopped before the end",
}

interface Form {
  start: string
  max: string
  step: string
  growth: string
  refine: string
  loss: string
  servfail: string
  p95: string
}

const DEFAULT_FORM: Form = {
  start: "200",
  max: "20000",
  step: "20",
  growth: "1.5",
  refine: "2",
  loss: "1",
  servfail: "1",
  p95: "100",
}

function StatusBadge({ status }: { status?: CapacityStatus }) {
  const value = status ?? "small"
  return (
    <Badge
      variant="outline"
      className={cn(
        "w-16 justify-center font-mono tracking-wide uppercase",
        STATUS_TONE[value]
      )}
    >
      {STATUS_LABEL[value]}
    </Badge>
  )
}

function NumberField({
  id,
  label,
  value,
  onChange,
  disabled,
  unit,
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  disabled: boolean
  unit?: string
}) {
  return (
    <Field>
      <FieldLabel htmlFor={id}>
        {label}
        {unit ? (
          <span className="font-normal text-muted-foreground">{unit}</span>
        ) : null}
      </FieldLabel>
      <Input
        id={id}
        type="number"
        min={0}
        step="any"
        inputMode="decimal"
        className="font-mono"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
      />
    </Field>
  )
}

/** A dot coloured by the step's verdict; Recharts passes it the point's props. */
function StatusDot(props: {
  cx?: number
  cy?: number
  payload?: { status?: CapacityStatus }
}) {
  if (props.cx === undefined || props.cy === undefined) return null
  return (
    <circle
      cx={props.cx}
      cy={props.cy}
      r={4.5}
      fill={STATUS_FILL[props.payload?.status ?? "small"]}
      stroke="var(--card)"
      strokeWidth={1.5}
    />
  )
}

const chartConfig = {
  p95: { label: "p95 ms", color: "var(--series-p95)" },
  loss: { label: "Loss %", color: "var(--series-timeout)" },
} satisfies ChartConfig

function CapacityChart({
  steps,
  slo,
}: {
  steps: CapacityStep[]
  slo?: CapacitySlo
}) {
  const data = steps
    .filter((step) => step.status !== "stopped")
    .map((step) => ({
      rate: step.target_qps,
      p95: num(step.p95_ms),
      loss: num(step.loss_pct),
      status: step.status,
    }))
    .sort((a, b) => a.rate - b.rate)
  if (data.length < 2) return null
  return (
    <div className="flex flex-col gap-2">
      <div>
        <p className="text-sm font-medium">Latency and loss by rate</p>
        <p className="text-xs text-muted-foreground">
          Each point is one step: green passed, red broke a limit. The dashed
          line is the p95 limit.
        </p>
      </div>
      <ChartContainer config={chartConfig} className="aspect-auto h-72 w-full">
        <ComposedChart
          data={data}
          margin={{ left: 4, right: 4, top: 8, bottom: 0 }}
        >
          <CartesianGrid vertical={false} />
          <XAxis
            dataKey="rate"
            type="number"
            scale="log"
            domain={["dataMin", "dataMax"]}
            ticks={data.map((point) => point.rate)}
            tickFormatter={(value: number) => fmtRate(value)}
            tickLine={false}
            axisLine={false}
            fontSize={11}
          />
          <YAxis
            yAxisId="ms"
            tickLine={false}
            axisLine={false}
            width={44}
            fontSize={11}
            tickFormatter={(value: number) => `${value}`}
          />
          <YAxis
            yAxisId="pct"
            orientation="right"
            tickLine={false}
            axisLine={false}
            width={40}
            fontSize={11}
            tickFormatter={(value: number) => `${value}%`}
          />
          {slo?.p95_ms ? (
            <ReferenceLine
              yAxisId="ms"
              y={slo.p95_ms}
              stroke="var(--muted-foreground)"
              strokeDasharray="4 4"
            />
          ) : null}
          <ChartTooltip
            content={
              <ChartTooltipContent
                labelFormatter={(_label, payload) =>
                  `${fmtRate(payload?.[0]?.payload?.rate)} qps`
                }
              />
            }
          />
          <ChartLegend content={<ChartLegendContent />} />
          <Line
            yAxisId="ms"
            dataKey="p95"
            stroke="var(--color-p95)"
            strokeWidth={2}
            dot={<StatusDot />}
            isAnimationActive={false}
          />
          <Line
            yAxisId="pct"
            dataKey="loss"
            stroke="var(--color-loss)"
            strokeWidth={1.5}
            strokeDasharray="5 3"
            dot={false}
            isAnimationActive={false}
          />
        </ComposedChart>
      </ChartContainer>
    </div>
  )
}

function StepsTable({ steps }: { steps: CapacityStep[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="pl-3">Step</TableHead>
            <TableHead className="text-right">Rate</TableHead>
            <TableHead className="text-right">Achieved</TableHead>
            <TableHead className="text-right">Loss</TableHead>
            <TableHead className="text-right">SERVFAIL</TableHead>
            <TableHead className="text-right">p50 ms</TableHead>
            <TableHead className="text-right">p95 ms</TableHead>
            <TableHead className="text-right">p99 ms</TableHead>
            <TableHead className="pr-3">Result</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {steps.map((step) => {
            const answered = num(step.received) > 0
            return (
              <TableRow key={step.index}>
                <TableCell className="pl-3 text-xs">
                  <span className="font-mono">#{step.index}</span>
                  <span className="ml-2 text-muted-foreground">
                    {step.phase === "refine" ? "narrowing" : "ramp"}
                  </span>
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {fmtRate(step.target_qps)}
                </TableCell>
                <TableCell className="text-right font-mono text-muted-foreground num">
                  {fmtRate(step.achieved_qps)}
                </TableCell>
                <TableCell
                  className={cn(
                    "text-right font-mono num",
                    num(step.loss_pct) > 1 && "text-bad"
                  )}
                >
                  {fmtPct(step.loss_pct)}
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {fmtPct(step.servfail_pct)}
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {answered ? fmtInt(step.p50_ms) : "-"}
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {answered ? fmtInt(step.p95_ms) : "-"}
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {answered ? fmtInt(step.p99_ms) : "-"}
                </TableCell>
                <TableCell className="pr-3">
                  <div className="flex items-start gap-2">
                    <StatusBadge status={step.status} />
                    {step.reasons?.length ? (
                      <span className="text-xs whitespace-normal text-muted-foreground">
                        {step.reasons.join("; ")}
                      </span>
                    ) : null}
                  </div>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

export function CapacityPage() {
  const run = useRun()
  const { snapshot } = useLive()
  const [polling, setPolling] = React.useState(false)
  const { data, refresh } = usePoll<CapacityPayload>(
    fetchCapacity,
    polling ? 1000 : 10000
  )
  const [target, setTarget] = React.useState("")
  const [form, setForm] = React.useState<Form>(DEFAULT_FORM)
  const now = useNow(1000)
  const chosen = target || run.target
  const selected = run.targets.find((t) => t.name === chosen)

  // Follow the server's state: poll quickly while the search runs.
  const state = data?.state
  const [seen, setSeen] = React.useState(state)
  if (state !== seen) {
    setSeen(state)
    setPolling(state === "running")
  }
  const running = state === "running"

  const value = (key: keyof Form) => Number.parseFloat(form[key])
  const update = (key: keyof Form) => (next: string) =>
    setForm((current) => ({ ...current, [key]: next }))
  const planned = ramp(value("start"), value("max"), value("growth"))
  const estimate = estimateSeconds(
    value("start"),
    value("max"),
    value("growth"),
    value("step"),
    value("refine")
  )
  const overPublic =
    selected?.kind === "public" && value("max") > PUBLIC_QPS_LIMIT
  const locked = running || run.running || DEMO

  const start = async () => {
    const result = await startCapacity({
      target: chosen || undefined,
      start_qps: value("start"),
      max_qps: value("max"),
      growth: value("growth"),
      step_s: value("step"),
      refine: value("refine"),
      slo: {
        loss_pct: value("loss"),
        servfail_pct: value("servfail"),
        p95_ms: value("p95"),
      },
    })
    if (result.ok) {
      toast.success(result.message)
      setPolling(true)
    } else toast.error(result.message)
    void refresh()
  }

  const steps = data?.steps ?? []
  const current = data?.current
  const stepSeconds = num(data?.plan?.step_s, 20)
  const elapsed = current?.started_at
    ? Math.max(0, now - current.started_at)
    : 0
  const result = data?.result

  return (
    <div className="flex flex-col gap-4 lg:gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Capacity search</CardTitle>
          <CardDescription>
            Raises the rate step by step, each step a run of the same office
            traffic, until the target breaks a limit you set; then narrows it
            down. The answer is the rate this mix of names is served at, and why
            the next step up failed.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          <div className="grid gap-4 @3xl/main:grid-cols-[minmax(0,2fr)_repeat(4,minmax(0,1fr))]">
            <Field>
              <FieldLabel htmlFor="capacity-target">Target</FieldLabel>
              <Select
                value={chosen}
                onValueChange={setTarget}
                disabled={locked}
              >
                <SelectTrigger id="capacity-target" className="w-full">
                  <SelectValue placeholder="Loading targets..." />
                </SelectTrigger>
                <SelectContent>
                  {run.targets.map((t) => (
                    <SelectItem key={t.name} value={t.name}>
                      {t.name}
                      <TransportBadge transport={t.transport} />
                      <span className="truncate font-mono text-xs text-muted-foreground">
                        {endpointOf(t)}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <NumberField
              id="capacity-start"
              label="Start"
              unit="qps"
              value={form.start}
              onChange={update("start")}
              disabled={locked}
            />
            <NumberField
              id="capacity-max"
              label="Highest"
              unit="qps"
              value={form.max}
              onChange={update("max")}
              disabled={locked}
            />
            <NumberField
              id="capacity-step"
              label="Each step"
              unit="s"
              value={form.step}
              onChange={update("step")}
              disabled={locked}
            />
            <NumberField
              id="capacity-growth"
              label="Growth"
              unit="x"
              value={form.growth}
              onChange={update("growth")}
              disabled={locked}
            />
          </div>
          <div className="grid gap-4 @xl/main:grid-cols-2 @3xl/main:grid-cols-[repeat(3,minmax(0,1fr))_minmax(0,2fr)]">
            <NumberField
              id="capacity-loss"
              label="Most loss"
              unit="%"
              value={form.loss}
              onChange={update("loss")}
              disabled={locked}
            />
            <NumberField
              id="capacity-servfail"
              label="Most SERVFAIL"
              unit="%"
              value={form.servfail}
              onChange={update("servfail")}
              disabled={locked}
            />
            <NumberField
              id="capacity-p95"
              label="Highest p95"
              unit="ms"
              value={form.p95}
              onChange={update("p95")}
              disabled={locked}
            />
            <div className="flex flex-col justify-end gap-2">
              <Button
                disabled={locked || !planned.length || !chosen}
                onClick={() => void start()}
              >
                {running ? <Spinner /> : <PlayIcon />}
                {running ? "Searching..." : "Run search"}
              </Button>
            </div>
          </div>
          <FieldDescription
            className={overPublic ? "text-warn" : undefined}
            aria-live="polite"
          >
            {overPublic
              ? `Public resolvers are capped at ${PUBLIC_QPS_LIMIT} qps unless the server was started with --allow-public-target.`
              : planned.length
                ? `${planned.length} ramp steps from ${fmtRate(planned[0])} to ${fmtRate(planned[planned.length - 1])} qps, then up to ${fmtInt(value("refine"))} to narrow it down: at most about ${Math.max(1, Math.round(estimate / 60))} min. A rate-limit error (EDE 31 or 32) on more than 0.5% of answers also breaks a step.`
                : "Set a starting rate, a higher highest rate and a growth above 1."}
          </FieldDescription>
          {run.running && !running && !DEMO ? (
            <p className="text-sm text-muted-foreground">
              Stop the load run first: a search sends its own traffic.
            </p>
          ) : null}
        </CardContent>
      </Card>

      {running && current ? (
        <Card>
          <CardHeader>
            <CardTitle>
              Step {current.index}: {fmtRate(current.target_qps)} qps
            </CardTitle>
            <CardDescription>
              {current.phase === "refine" ? "Narrowing down" : "Ramping up"} -
              the Live run page shows this step in full. Stop it from the
              header.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <Progress value={Math.min(100, (100 * elapsed) / stepSeconds)} />
            <dl className="grid grid-cols-3 gap-4">
              {[
                ["Sent qps", fmtRate(snapshot?.rates?.qps_sent)],
                ["p95 ms", fmtInt(snapshot?.latency_ms?.p95)],
                ["Loss", fmtPct(snapshot?.rates?.window_error_pct)],
              ].map(([label, shown]) => (
                <div key={label} className="flex flex-col gap-0.5">
                  <dt className="text-xs text-muted-foreground">{label}</dt>
                  <dd className="font-mono text-lg num">{shown}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      ) : null}

      {steps.length ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2">
              {data?.target?.name ?? "Results"}
              <TransportBadge transport={data?.target?.transport} />
              <span className="font-mono text-sm font-normal text-muted-foreground">
                {endpointOf(data?.target)}
              </span>
            </CardTitle>
            <CardDescription>
              {data?.finished_at
                ? `Searched ${fmtDateTime(data.finished_at)}`
                : "Searching..."}
              {` - ${steps.length} step${steps.length === 1 ? "" : "s"} of ${num(data?.plan?.step_s, 20)}s`}
            </CardDescription>
            <CardAction>
              <Button variant="outline" size="sm" asChild>
                <a
                  href={DEMO ? undefined : DOWNLOADS.capacity}
                  download
                  aria-disabled={DEMO || undefined}
                >
                  <DownloadIcon />
                  Export JSON
                </a>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-6">
            {result ? (
              <div className="flex flex-wrap items-end gap-x-10 gap-y-3">
                <div className="flex flex-col gap-1">
                  <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                    Sustains
                  </p>
                  <p className="font-mono text-4xl font-semibold num">
                    {typeof result.sustained_qps === "number"
                      ? fmtRate(result.sustained_qps)
                      : "-"}
                    <span className="ml-1.5 text-base font-normal text-muted-foreground">
                      qps
                    </span>
                  </p>
                </div>
                {typeof result.knee_qps === "number" ? (
                  <div className="flex flex-col gap-1">
                    <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                      Breaks at
                    </p>
                    <p className="font-mono text-2xl text-bad num">
                      {fmtRate(result.knee_qps)}
                      <span className="ml-1.5 text-sm font-normal text-muted-foreground">
                        qps
                      </span>
                    </p>
                  </div>
                ) : null}
                <div className="flex min-w-60 flex-1 flex-col gap-1">
                  <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                    {LIMIT_TEXT[result.limit ?? "stopped"] ?? ""}
                  </p>
                  <p className="text-sm">{result.summary}</p>
                </div>
              </div>
            ) : null}
            <CapacityChart steps={steps} slo={data?.slo} />
            <StepsTable steps={steps} />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent>
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  {running ? <Spinner /> : <GaugeIcon />}
                </EmptyMedia>
                <EmptyTitle>
                  {running ? "Starting the first step..." : "No search yet"}
                </EmptyTitle>
                <EmptyDescription>
                  {data?.state === "error"
                    ? `The search failed: ${data.error}`
                    : "Pick a target and the limits it must meet, then press Run search."}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
