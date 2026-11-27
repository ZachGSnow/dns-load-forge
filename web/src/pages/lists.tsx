import { CircleAlertIcon, RefreshCwIcon } from "lucide-react"
import * as React from "react"
import { toast } from "sonner"

import { useRun } from "@/components/run-context"
import { categoryTone } from "@/components/status"
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
import { Progress } from "@/components/ui/progress"
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
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { usePoll } from "@/hooks/use-poll"
import { cn } from "@/lib/utils"
import { DEMO } from "@/lib/api"
import { fmtAge, fmtInt, num, relTime } from "@/lib/format"
import {
  fetchLists,
  fetchSources,
  refreshSources,
  setSourceEnabled,
  type ActionResult,
} from "@/lib/resources"
import type { SourceJob, SourcesPayload } from "@/lib/schema"

function jobLine(
  job: SourceJob | undefined,
  available: boolean | undefined
): { text: string; error: boolean } {
  if (!job || job.state === "idle" || !job.state) {
    return {
      text:
        available === false
          ? "List management is not available in this session."
          : "",
      error: false,
    }
  }
  if (job.state === "running") {
    return {
      text: `${job.kind === "refresh" ? "Refreshing" : "Updating"} ${job.current || "..."} (${fmtInt(job.done)} of ${fmtInt(job.total)})`,
      error: false,
    }
  }
  if (job.state === "error")
    return {
      text: `Update failed: ${job.error || "unknown error"}`,
      error: true,
    }
  const results = job.results ?? []
  const failed = results.filter((r) => r.status === "failed")
  const updated = results.filter((r) => r.status === "updated").length
  if (!results.length) return { text: "Catalogue rebuilt.", error: false }
  return {
    text: `Finished: ${updated} updated, ${results.length - updated - failed.length} unchanged${
      failed.length ? `, ${failed.length} failed (kept the cached copy)` : ""
    }.`,
    error: failed.length > 0,
  }
}

export function ListsPage() {
  const run = useRun()
  const [jobRunning, setJobRunning] = React.useState(false)
  const { data: lists, refresh: refreshLists } = usePoll(fetchLists, 30000)
  // Poll quickly only while a list update runs.
  const { data: sources, refresh: reloadSources } = usePoll<SourcesPayload>(
    fetchSources,
    jobRunning ? 1500 : 30000
  )
  const job = sources?.job

  // The job state arrives with each poll; follow it, and when a job has just
  // finished re-read the catalogue, whose category counts it changed.
  const state = job?.state
  const [seenState, setSeenState] = React.useState(state)
  if (state !== seenState) {
    setSeenState(state)
    setJobRunning(state === "running")
    if (seenState === "running" && state !== "running") void refreshLists()
  }

  const blocked =
    run.running || jobRunning || DEMO || sources?.available === false
  const status = jobLine(job, sources?.available)
  const failures = (job?.results ?? []).filter((r) => r.status === "failed")

  const report = (result: ActionResult) => {
    if (result.ok) toast.success(result.message)
    else toast.error(result.message)
    void reloadSources()
  }

  const categories = lists?.categories ?? []
  const fetched = num(lists?.fetched_at)

  return (
    <div className="flex flex-col gap-4 lg:gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Catalogue</CardTitle>
          <CardDescription>
            What the next run draws from.{" "}
            {lists?.cache_dir ? (
              <>
                Cached in <span className="font-mono">{lists.cache_dir}</span>
                {fetched > 0
                  ? `, fetched ${relTime(fetched)}`
                  : ", not fetched yet"}
                {lists.offline ? " (offline)" : ""}.
              </>
            ) : null}
          </CardDescription>
          <CardAction>
            <Badge variant="secondary" className="font-mono num">
              {fmtInt(lists?.total)} names
            </Badge>
          </CardAction>
        </CardHeader>
        <CardContent>
          {categories.length ? (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5">
              {categories.map((row) => (
                <div
                  key={row.category}
                  className="flex flex-col gap-1 rounded-lg border bg-muted/20 p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">
                      {row.label || row.category}
                    </span>
                    <Badge
                      variant="outline"
                      className={cn(
                        "font-mono font-normal num",
                        categoryTone(row.category)
                      )}
                    >
                      {fmtInt(row.count)}
                    </Badge>
                  </div>
                  <span
                    className="truncate font-mono text-xs text-muted-foreground"
                    title={row.source || "built-in"}
                  >
                    {row.category === "nxdomain_probe" && !row.count
                      ? "generated per run"
                      : row.source || "built-in"}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              List inventory unavailable.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sources</CardTitle>
          <CardDescription>
            Lists only change between runs: re-parsing a million-name list
            mid-run would distort the latency being measured. Refreshing or
            switching a source off rebuilds the catalogue (about 15 seconds) and
            needs internet; a failed download keeps the cached copy.
            {run.running
              ? " A run is in progress, so these controls are locked until it stops."
              : ""}
          </CardDescription>
          <CardAction>
            <Button
              variant="outline"
              size="sm"
              disabled={blocked}
              onClick={async () => report(await refreshSources())}
            >
              {jobRunning ? <Spinner /> : <RefreshCwIcon />}
              Refresh all
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 px-0">
          {status.text ? (
            <div className="flex flex-col gap-2 px-4">
              <p
                className={cn(
                  "flex items-center gap-2 text-sm",
                  status.error ? "text-bad" : "text-muted-foreground"
                )}
                role="status"
              >
                {status.error ? <CircleAlertIcon className="size-4" /> : null}
                {status.text}
              </p>
              {jobRunning ? (
                <Progress
                  value={Math.min(
                    100,
                    (100 * num(job?.done)) / Math.max(1, num(job?.total))
                  )}
                />
              ) : null}
              {failures.length ? (
                <ul className="list-inside list-disc text-xs text-muted-foreground">
                  {failures.map((f) => (
                    <li key={f.slug}>
                      <span className="font-mono">{f.slug}</span>: {f.error}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          {sources?.error ? (
            <p className="px-4 text-sm text-bad">{sources.error}</p>
          ) : null}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-4">Source</TableHead>
                <TableHead>Category</TableHead>
                <TableHead className="text-right">Names</TableHead>
                <TableHead className="text-right">Fetched</TableHead>
                <TableHead className="text-center">On</TableHead>
                <TableHead className="pr-4 text-right">Update</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(sources?.sources ?? []).map((row) => (
                <TableRow
                  key={row.slug}
                  className={cn(!row.enabled && "opacity-60")}
                >
                  <TableCell className="pl-4">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="cursor-help font-mono">
                          {row.slug}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent className="max-w-sm">
                        <p>{row.description || row.slug}</p>
                        {row.url ? (
                          <p className="font-mono text-xs break-all opacity-80">
                            {row.url}
                          </p>
                        ) : null}
                      </TooltipContent>
                    </Tooltip>
                    {row.description ? (
                      <p className="max-w-md truncate text-xs text-muted-foreground">
                        {row.description}
                      </p>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={cn(
                        "font-mono font-normal",
                        categoryTone(row.category)
                      )}
                    >
                      {row.category}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right font-mono num">
                    {row.count ? fmtInt(row.count) : "-"}
                  </TableCell>
                  <TableCell
                    className={cn(
                      "text-right font-mono num",
                      row.stale && "text-warn"
                    )}
                    title={
                      row.stale
                        ? "older than the 7 day trust window"
                        : undefined
                    }
                  >
                    {fmtAge(row.age_s)}
                  </TableCell>
                  <TableCell className="text-center">
                    <Switch
                      checked={!!row.enabled}
                      disabled={blocked}
                      aria-label={`Use ${row.slug}`}
                      onCheckedChange={async (checked) =>
                        report(await setSourceEnabled(row.slug, checked))
                      }
                    />
                  </TableCell>
                  <TableCell className="pr-4 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={blocked}
                      onClick={async () =>
                        report(await refreshSources([row.slug]))
                      }
                    >
                      <RefreshCwIcon />
                      Refresh
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {sources && !(sources.sources ?? []).length ? (
            <p className="px-4 text-sm text-muted-foreground">
              Source management is not available in this session.
            </p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}
