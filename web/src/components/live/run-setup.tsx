import { DownloadIcon, PlayIcon, SquareIcon } from "lucide-react"

import { useRun } from "@/components/run-context"
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { TransportBadge } from "@/components/transport-badge"
import { Separator } from "@/components/ui/separator"
import { Spinner } from "@/components/ui/spinner"
import { DEMO, DOWNLOADS } from "@/lib/api"
import { fmtDuration, fmtInt, fmtRate, num } from "@/lib/format"
import { useLive } from "@/lib/live"
import type { Target } from "@/lib/schema"
import { endpointOf } from "@/lib/transport"

/** Above this rate a public resolver needs --allow-public-target (targets.py). */
const PUBLIC_QPS_LIMIT = 100

function TargetItem({ target }: { target: Target }) {
  return (
    <SelectItem value={target.name}>
      {target.name}
      <TransportBadge transport={target.transport} />
      <span className="truncate font-mono text-xs text-muted-foreground">
        {endpointOf(target)}
      </span>
    </SelectItem>
  )
}

function Detail({
  label,
  value,
  mono = true,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd
        className={mono ? "truncate font-mono text-sm num" : "truncate text-sm"}
      >
        {value}
      </dd>
    </div>
  )
}

function ExportMenu() {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={DEMO}>
          <DownloadIcon />
          Export
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuLabel className="font-normal text-muted-foreground">
          Per-query evidence for this run. Needs the server started with
          --record-log.
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {(["csv", "jsonl", "json"] as const).map((format) => (
          <DropdownMenuItem key={format} asChild>
            <a href={DOWNLOADS[format]} download>
              {format.toUpperCase()}
            </a>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function RunSetup() {
  const run = useRun()
  const { snapshot } = useLive()
  const info = snapshot?.run
  const selected = run.targets.find((t) => t.name === run.target)
  const qps = Number.parseFloat(run.qps)
  const overPublicLimit =
    selected?.kind === "public" &&
    Number.isFinite(qps) &&
    qps > PUBLIC_QPS_LIMIT
  const appliances = run.targets.filter((t) => t.kind !== "public")
  const publics = run.targets.filter((t) => t.kind === "public")
  const planTotal = num(info?.plan_total)
  const locked = run.running || DEMO

  return (
    <Card>
      <CardHeader>
        <CardTitle>Run</CardTitle>
        <CardDescription>
          {run.running
            ? `Sending to ${info?.target_name || info?.server || "the target"}. Settings apply to the next run.`
            : "Pick a target, a rate and a duration, then press Start."}
        </CardDescription>
        <CardAction>
          <ExportMenu />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid items-start gap-3 @2xl/main:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)_auto]">
          <Field>
            <FieldLabel htmlFor="run-target">Test against</FieldLabel>
            <Select
              value={run.target}
              onValueChange={run.setTarget}
              disabled={locked}
            >
              <SelectTrigger id="run-target" className="w-full">
                <SelectValue placeholder="Loading targets..." />
              </SelectTrigger>
              <SelectContent>
                {appliances.length ? (
                  <SelectGroup>
                    <SelectLabel>Appliances</SelectLabel>
                    {appliances.map((t) => (
                      <TargetItem key={t.name} target={t} />
                    ))}
                  </SelectGroup>
                ) : null}
                {publics.length ? (
                  <SelectGroup>
                    <SelectLabel>Public resolvers</SelectLabel>
                    {publics.map((t) => (
                      <TargetItem key={t.name} target={t} />
                    ))}
                  </SelectGroup>
                ) : null}
              </SelectContent>
            </Select>
            {selected?.notes ? (
              <FieldDescription>{selected.notes}</FieldDescription>
            ) : null}
          </Field>
          <Field data-invalid={overPublicLimit || undefined}>
            <FieldLabel htmlFor="run-qps">Queries per second</FieldLabel>
            <Input
              id="run-qps"
              type="number"
              min={1}
              step={1}
              inputMode="numeric"
              className="font-mono"
              value={run.qps}
              disabled={locked}
              aria-invalid={overPublicLimit || undefined}
              onChange={(event) => run.setQps(event.target.value)}
            />
            {overPublicLimit ? (
              <FieldDescription className="text-warn">
                Public resolvers are capped at {PUBLIC_QPS_LIMIT} qps unless the
                server was started with --allow-public-target.
              </FieldDescription>
            ) : null}
          </Field>
          <Field>
            <FieldLabel htmlFor="run-duration">Seconds</FieldLabel>
            <Input
              id="run-duration"
              type="number"
              min={0}
              step={1}
              inputMode="numeric"
              className="font-mono"
              value={run.duration}
              disabled={locked}
              onChange={(event) => run.setDuration(event.target.value)}
            />
            <FieldDescription>0 runs until you press Stop.</FieldDescription>
          </Field>
          <div className="flex gap-2 @2xl/main:pt-6">
            {run.running ? (
              <Button
                variant="destructive"
                disabled={run.busy || DEMO}
                onClick={() => void run.stop()}
              >
                {run.busy ? <Spinner /> : <SquareIcon />}
                Stop
              </Button>
            ) : (
              <Button
                disabled={run.busy || DEMO || !run.target}
                onClick={() => void run.start()}
              >
                {run.busy ? <Spinner /> : <PlayIcon />}
                Start
              </Button>
            )}
          </div>
        </div>
        <Separator />
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 @lg/main:grid-cols-4 @4xl/main:grid-cols-8">
          <Detail
            label="Target"
            mono={false}
            value={info?.target_name || info?.server || "-"}
          />
          <Detail label="Endpoint" value={info?.server || "-"} />
          <Detail
            label="Comparison"
            value={
              planTotal > 1 ? (
                <Badge variant="secondary">
                  {fmtInt(info?.plan_index)} of {fmtInt(planTotal)}
                </Badge>
              ) : (
                "-"
              )
            }
          />
          <Detail label="Identity" mono={false} value={info?.mode ?? "-"} />
          <Detail
            label="Workers"
            value={info?.personas !== undefined ? fmtInt(info.personas) : "-"}
          />
          <Detail
            label="Source IPs"
            value={
              info?.source_ips !== undefined ? fmtInt(info.source_ips) : "-"
            }
          />
          <Detail
            label="Target qps"
            value={
              info?.target_qps !== undefined ? fmtRate(info.target_qps) : "-"
            }
          />
          <Detail label="Elapsed" value={fmtDuration(info?.elapsed_s)} />
        </dl>
      </CardContent>
    </Card>
  )
}
