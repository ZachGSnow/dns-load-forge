import { ChevronRightIcon, ListChecksIcon, PlayIcon } from "lucide-react"
import * as React from "react"
import { toast } from "sonner"

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
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Spinner } from "@/components/ui/spinner"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { usePoll } from "@/hooks/use-poll"
import { DEMO } from "@/lib/api"
import { fmtDateTime, fmtMs } from "@/lib/format"
import { fetchChecks, runChecks } from "@/lib/resources"
import type { CheckResult, CheckStatus, ChecksPayload } from "@/lib/schema"
import { cn } from "@/lib/utils"

const STATUS_ORDER: CheckStatus[] = [
  "fail",
  "warn",
  "error",
  "pass",
  "info",
  "skip",
]

const STATUS_LABEL: Record<CheckStatus, string> = {
  fail: "Fail",
  warn: "Warn",
  error: "Error",
  pass: "Pass",
  info: "Info",
  skip: "Skipped",
}

const STATUS_TONE: Record<CheckStatus, string> = {
  fail: "text-bad border-bad/40 bg-bad/10",
  warn: "text-warn border-warn/40 bg-warn/10",
  error: "text-fp border-fp/40 bg-fp/10",
  pass: "text-ok border-ok/40 bg-ok/10",
  info: "text-info border-info/40 bg-info/10",
  skip: "text-muted-foreground",
}

const GROUP_ORDER = [
  "Resolver",
  "This network",
  "Encrypted DNS",
  "Security",
  "Content controls",
  "Policy",
  "Errors",
]

function StatusBadge({ status }: { status: CheckStatus }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "w-16 justify-center font-mono tracking-wide uppercase",
        STATUS_TONE[status]
      )}
    >
      {STATUS_LABEL[status]}
    </Badge>
  )
}

function Evidence({ result }: { result: CheckResult }) {
  const rows = result.evidence ?? []
  if (!rows.length) return null
  const vendor = rows.some((row) => row.vendor)
  return (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            {vendor ? <TableHead className="pl-3">Vendor</TableHead> : null}
            <TableHead className={vendor ? undefined : "pl-3"}>Query</TableHead>
            <TableHead>Server</TableHead>
            <TableHead>RCODE</TableHead>
            <TableHead>Answer</TableHead>
            <TableHead>EDE / NSID</TableHead>
            <TableHead className="pr-3 text-right">ms</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row, index) => (
            <TableRow key={`${row.qname}-${row.qtype}-${index}`}>
              {vendor ? (
                <TableCell className="pl-3 text-xs">
                  <div>{row.vendor}</div>
                  <div className="text-muted-foreground">{row.kind}</div>
                </TableCell>
              ) : null}
              <TableCell
                className={cn("font-mono text-xs", vendor ? undefined : "pl-3")}
              >
                <span className="text-muted-foreground">{row.qtype} </span>
                {row.qname}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {row.server}
              </TableCell>
              <TableCell className="font-mono text-xs">{row.rcode}</TableCell>
              <TableCell
                className={cn(
                  "max-w-80 truncate font-mono text-xs",
                  row.blocked ? "text-ok" : undefined,
                  row.error ? "text-muted-foreground" : undefined
                )}
                title={row.answer}
              >
                {row.blocked ? `blocked: ${row.blocked}` : row.answer}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {[row.ede, row.nsid, row.ad ? "AD" : ""]
                  .filter(Boolean)
                  .join(" / ") || "-"}
              </TableCell>
              <TableCell className="pr-3 text-right font-mono text-xs num">
                {row.error ? "-" : fmtMs(row.latency_ms)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function ResultRow({ result }: { result: CheckResult }) {
  const [open, setOpen] = React.useState(false)
  const hasMore = Boolean(result.detail || result.evidence?.length)
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div className="flex items-start gap-3 py-3">
        <StatusBadge status={result.status} />
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="text-sm font-medium">{result.title}</div>
          <p className="text-sm text-muted-foreground">{result.summary}</p>
        </div>
        {hasMore ? (
          <CollapsibleTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              aria-label={open ? "Hide evidence" : "Show evidence"}
            >
              Evidence
              <ChevronRightIcon
                className={cn("transition-transform", open && "rotate-90")}
              />
            </Button>
          </CollapsibleTrigger>
        ) : null}
      </div>
      <CollapsibleContent className="flex flex-col gap-3 pb-4 pl-19">
        {result.detail ? (
          <p className="text-sm text-muted-foreground">{result.detail}</p>
        ) : null}
        <Evidence result={result} />
      </CollapsibleContent>
    </Collapsible>
  )
}

export function ChecksPage() {
  const run = useRun()
  const [running, setRunning] = React.useState(false)
  const { data, refresh } = usePoll<ChecksPayload>(
    fetchChecks,
    running ? 1000 : 15000
  )
  const [target, setTarget] = React.useState("")
  const [network, setNetwork] = React.useState(true)
  const chosen = target || run.target

  // Follow the server's state: poll quickly while the checks run.
  const state = data?.state
  const [seen, setSeen] = React.useState(state)
  if (state !== seen) {
    setSeen(state)
    setRunning(state === "running")
  }

  const results = data?.results ?? []
  const counts = STATUS_ORDER.map((status) => ({
    status,
    count: results.filter((result) => result.status === status).length,
  })).filter((item) => item.count > 0)
  const groups = GROUP_ORDER.map((group) => ({
    group,
    rows: results.filter((result) => result.group === group),
  })).filter((item) => item.rows.length > 0)

  const start = async () => {
    const result = await runChecks(chosen || undefined, network)
    if (result.ok) {
      toast.success(result.message)
      setRunning(true)
    } else toast.error(result.message)
    void refresh()
  }

  const locked = run.running || running || DEMO

  return (
    <div className="flex flex-col gap-4 lg:gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Deployment checks</CardTitle>
          <CardDescription>
            Before the load test: which resolver really answers, whether DNS can
            go around the filter, and whether it turns off the encrypted-DNS
            escape hatches, validates DNSSEC and enforces SafeSearch. A few
            dozen queries in all.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-end gap-4">
          <Field className="w-full max-w-sm">
            <FieldLabel htmlFor="checks-target">Target</FieldLabel>
            <Select value={chosen} onValueChange={setTarget} disabled={locked}>
              <SelectTrigger id="checks-target" className="w-full">
                <SelectValue placeholder="Loading targets..." />
              </SelectTrigger>
              <SelectContent>
                {run.targets.map((t) => (
                  <SelectItem key={t.name} value={t.name}>
                    {t.name}
                    <span className="font-mono text-xs text-muted-foreground">
                      {t.server}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field orientation="horizontal" className="w-auto">
            <Switch
              id="checks-network"
              checked={network}
              onCheckedChange={setNetwork}
              disabled={locked}
            />
            <div className="flex flex-col">
              <FieldLabel htmlFor="checks-network">
                Check this machine&apos;s network too
              </FieldLabel>
              <FieldDescription>
                Interception and bypass: sends a few queries to public
                resolvers.
              </FieldDescription>
            </div>
          </Field>
          <Button disabled={locked} onClick={() => void start()}>
            {running ? <Spinner /> : <PlayIcon />}
            {running ? "Checking..." : "Run checks"}
          </Button>
          {run.running ? (
            <p className="text-sm text-muted-foreground">
              Stop the load run first: the checks would skew its latency.
            </p>
          ) : null}
        </CardContent>
      </Card>

      {results.length ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {data?.target?.name ?? "Results"}
              <span className="ml-2 font-mono text-sm font-normal text-muted-foreground">
                {data?.target?.server}
              </span>
            </CardTitle>
            <CardDescription>
              {data?.finished_at
                ? `Checked ${fmtDateTime(data.finished_at)}`
                : "Checking..."}
              {data?.network === false ? " - network checks left out" : ""}
              {running && data?.current ? ` - running ${data.current}` : ""}
            </CardDescription>
            <CardAction className="flex flex-wrap justify-end gap-1.5">
              {counts.map(({ status, count }) => (
                <Badge
                  key={status}
                  variant="outline"
                  className={cn("num", STATUS_TONE[status])}
                >
                  {count} {STATUS_LABEL[status].toLowerCase()}
                </Badge>
              ))}
            </CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-6">
            {groups.map(({ group, rows }) => (
              <section key={group}>
                <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                  {group}
                </h3>
                <div className="divide-y">
                  {rows.map((result) => (
                    <ResultRow key={result.id} result={result} />
                  ))}
                </div>
              </section>
            ))}
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent>
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  {running ? <Spinner /> : <ListChecksIcon />}
                </EmptyMedia>
                <EmptyTitle>
                  {running ? "Running the checks..." : "No checks yet"}
                </EmptyTitle>
                <EmptyDescription>
                  {data?.state === "error"
                    ? `The checks failed: ${data.error}`
                    : "Pick a target and press Run checks."}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
