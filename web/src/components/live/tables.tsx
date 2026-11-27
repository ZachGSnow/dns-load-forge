import {
  ArrowDownIcon,
  ArrowUpDownIcon,
  ArrowUpIcon,
  CircleCheckIcon,
} from "lucide-react"
import * as React from "react"

import { CategoryBadge, ExpectBadge } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { cn } from "@/lib/utils"
import {
  MAX_TABLE_ROWS,
  OUTCOME_LABELS,
  OUTCOME_TONE,
  type Outcome,
} from "@/lib/constants"
import { fmtFraction, fmtInt, fmtMs, num, relTime } from "@/lib/format"
import type { ClientRow, DomainRow, FindingRow, Snapshot } from "@/lib/schema"
import { categoryRows } from "@/lib/snapshot"

function Count({ value, tone }: { value: number; tone: string }) {
  return (
    <span
      className={cn(
        "font-mono num",
        value > 0 ? tone : "text-muted-foreground/70"
      )}
    >
      {fmtInt(value)}
    </span>
  )
}

function PassRate({ value }: { value: number | null }) {
  if (value === null) return <span className="text-muted-foreground">-</span>
  const low = value < 0.95
  return (
    <div className="flex items-center justify-end gap-2">
      <div className="hidden h-1.5 w-16 overflow-hidden rounded-full bg-muted sm:block">
        <div
          className={cn("h-full rounded-full", low ? "bg-bad" : "bg-ok")}
          style={{ width: `${(value * 100).toFixed(1)}%` }}
        />
      </div>
      <span className={cn("w-14 text-right font-mono num", low && "text-bad")}>
        {fmtFraction(value)}
      </span>
    </div>
  )
}

export function CategoryTable({ snapshot }: { snapshot: Snapshot | null }) {
  const rows = categoryRows(snapshot)
  const any = rows.some((row) => row.sent > 0)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Results by domain category</CardTitle>
        <CardDescription>
          FP is an allow-listed name that was blocked (an outage); FN is a
          block-listed name that resolved (a gap). Borderline traffic is
          reported, never judged.
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">Category</TableHead>
              <TableHead>Expect</TableHead>
              <TableHead className="text-right">Sent</TableHead>
              <TableHead className="text-right">Blocked</TableHead>
              <TableHead className="text-right">Allowed</TableHead>
              <TableHead className="text-right">NXDOMAIN</TableHead>
              <TableHead className="text-right">FP</TableHead>
              <TableHead className="text-right">FN</TableHead>
              <TableHead className="text-right">Timeout</TableHead>
              <TableHead className="text-right">p95 ms</TableHead>
              <TableHead className="pr-4 text-right">Pass rate</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow
                key={row.category}
                className={row.sent === 0 ? "opacity-60" : undefined}
              >
                <TableCell className="pl-4 font-medium">{row.label}</TableCell>
                <TableCell>
                  <ExpectBadge expect={row.expect} />
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {fmtInt(row.sent)}
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {fmtInt(row.blocked)}
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {fmtInt(row.allowed)}
                </TableCell>
                <TableCell className="text-right font-mono text-muted-foreground num">
                  {fmtInt(row.nxdomain)}
                </TableCell>
                <TableCell className="text-right">
                  <Count value={row.fp} tone="font-semibold text-fp" />
                </TableCell>
                <TableCell className="text-right">
                  <Count value={row.fn} tone="font-semibold text-fn" />
                </TableCell>
                <TableCell className="text-right">
                  <Count value={row.timeout} tone="text-warn" />
                </TableCell>
                <TableCell className="text-right font-mono num">
                  {fmtMs(row.p95)}
                </TableCell>
                <TableCell className="pr-4">
                  <PassRate value={row.sent > 0 ? row.passRate : null} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!any ? (
          <p className="px-4 pt-3 text-sm text-muted-foreground">
            Waiting for the first query results...
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}

export function FindingsCard({
  kind,
  rows,
}: {
  kind: "fp" | "fn"
  rows: FindingRow[]
}) {
  const fp = kind === "fp"
  const tone = fp ? "text-fp" : "text-fn"
  const hot = rows.length > 0
  return (
    <Card
      className={cn(
        hot &&
          (fp
            ? "shadow-lg shadow-fp/15 ring-fp/50"
            : "shadow-lg shadow-fn/15 ring-fn/50")
      )}
    >
      <CardHeader>
        <CardTitle className={cn(hot ? tone : "text-foreground")}>
          {fp ? "False positives" : "False negatives"}
        </CardTitle>
        <CardDescription>
          {fp
            ? "Allow-listed domains that were blocked"
            : "Block-listed domains that resolved"}
        </CardDescription>
        <CardAction>
          <Badge
            variant="outline"
            className={cn(
              "font-mono num",
              hot ? tone : "text-muted-foreground"
            )}
          >
            {fmtInt(rows.length)}
          </Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="px-0">
        {hot ? (
          <div className="max-h-80 overflow-auto">
            <Table className="table-fixed">
              <TableHeader className="sticky top-0 z-10 bg-card">
                <TableRow>
                  <TableHead className="pl-4">Domain</TableHead>
                  <TableHead className={fp ? "w-28" : "w-36"}>
                    {fp ? "RCODE" : "Answer"}
                  </TableHead>
                  <TableHead className="w-16 text-right">Hits</TableHead>
                  <TableHead className="w-24 pr-4 text-right">
                    Last seen
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.slice(0, 20).map((row) => (
                  <TableRow key={`${row.qname}|${row.client_ip}`}>
                    <TableCell className="pl-4">
                      <div className="truncate font-mono" title={row.qname}>
                        {row.qname}
                      </div>
                      <div className="flex gap-3 truncate font-mono text-xs text-muted-foreground">
                        {row.qtype ? (
                          <span className="text-foreground">{row.qtype}</span>
                        ) : null}
                        <span>{row.client_ip || "-"}</span>
                        <span>{row.category || "-"}</span>
                      </div>
                    </TableCell>
                    <TableCell
                      className={cn(
                        "truncate font-mono",
                        fp && "font-semibold text-bad"
                      )}
                      title={fp ? row.rcode : row.answer}
                    >
                      {(fp ? row.rcode : row.answer) || "-"}
                      {row.ede ? (
                        <div className="truncate text-xs font-normal text-muted-foreground">
                          EDE {row.ede}
                        </div>
                      ) : null}
                    </TableCell>
                    <TableCell
                      className={cn(
                        "text-right font-mono font-semibold num",
                        tone
                      )}
                    >
                      {fmtInt(row.count)}
                    </TableCell>
                    <TableCell className="pr-4 text-right font-mono text-muted-foreground num">
                      {relTime(row.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <p className="flex items-center gap-2 px-4 text-sm text-ok">
            <CircleCheckIcon className="size-4" />
            {fp
              ? "No allow-listed domain was blocked. Good news."
              : "No block-listed domain resolved. Good news."}
          </p>
        )}
      </CardContent>
    </Card>
  )
}

type SortKey = "qname" | "category" | "outcome" | "count" | "p95"

function SortHead({
  label,
  column,
  sort,
  onSort,
  className,
}: {
  label: string
  column: SortKey
  sort: { key: SortKey; dir: "asc" | "desc" }
  onSort: (key: SortKey) => void
  className?: string
}) {
  const active = sort.key === column
  const Icon = !active
    ? ArrowUpDownIcon
    : sort.dir === "asc"
      ? ArrowUpIcon
      : ArrowDownIcon
  const numeric = column === "count" || column === "p95"
  return (
    <TableHead
      className={className}
      aria-sort={
        active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"
      }
    >
      <button
        type="button"
        onClick={() => onSort(column)}
        className={cn(
          "inline-flex items-center gap-1 rounded-sm hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
          numeric && "flex-row-reverse",
          active && "text-foreground"
        )}
      >
        {label}
        <Icon className={cn("size-3.5", !active && "opacity-40")} />
      </button>
    </TableHead>
  )
}

export function TopDomains({
  rows,
  unique,
}: {
  rows: DomainRow[]
  unique: number
}) {
  const [sort, setSort] = React.useState<{ key: SortKey; dir: "asc" | "desc" }>(
    { key: "count", dir: "desc" }
  )
  const onSort = (key: SortKey) =>
    setSort((current) =>
      current.key === key
        ? { key, dir: current.dir === "desc" ? "asc" : "desc" }
        : {
            key,
            dir:
              key === "qname" || key === "category" || key === "outcome"
                ? "asc"
                : "desc",
          }
    )
  const sorted = React.useMemo(() => {
    const copy = rows.slice()
    copy.sort((a, b) => {
      const cmp =
        sort.key === "count" || sort.key === "p95"
          ? num(a[sort.key]) - num(b[sort.key])
          : String(a[sort.key] ?? "").localeCompare(String(b[sort.key] ?? ""))
      return sort.dir === "asc" ? cmp : -cmp
    })
    return copy.slice(0, MAX_TABLE_ROWS)
  }, [rows, sort])

  return (
    <Card className="@2xl/main:col-span-2">
      <CardHeader>
        <CardTitle>Top queried domains</CardTitle>
        <CardDescription>
          {rows.length
            ? `Showing ${Math.min(rows.length, MAX_TABLE_ROWS)} of ${fmtInt(unique)} unique names. Click a column to sort.`
            : "Waiting for the first query results..."}
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <div className="max-h-96 overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <SortHead
                  label="Domain"
                  column="qname"
                  sort={sort}
                  onSort={onSort}
                  className="pl-4"
                />
                <SortHead
                  label="Category"
                  column="category"
                  sort={sort}
                  onSort={onSort}
                />
                <SortHead
                  label="Outcome"
                  column="outcome"
                  sort={sort}
                  onSort={onSort}
                />
                <SortHead
                  label="Count"
                  column="count"
                  sort={sort}
                  onSort={onSort}
                  className="text-right"
                />
                <SortHead
                  label="p95 ms"
                  column="p95"
                  sort={sort}
                  onSort={onSort}
                  className="pr-4 text-right"
                />
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.map((row) => {
                const outcome = row.outcome as Outcome
                return (
                  <TableRow key={row.qname}>
                    <TableCell
                      className="max-w-80 truncate pl-4 font-mono"
                      title={row.qname}
                    >
                      {row.qname}
                    </TableCell>
                    <TableCell>
                      <CategoryBadge category={row.category} />
                    </TableCell>
                    <TableCell
                      className={cn(
                        "font-mono text-xs",
                        OUTCOME_TONE[outcome] ?? "text-muted-foreground"
                      )}
                    >
                      {OUTCOME_LABELS[outcome] ?? row.outcome ?? "-"}
                    </TableCell>
                    <TableCell className="text-right font-mono num">
                      {fmtInt(row.count)}
                    </TableCell>
                    <TableCell className="pr-4 text-right font-mono num">
                      {fmtMs(row.p95)}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}

export function TopClients({ rows }: { rows: ClientRow[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Top clients</CardTitle>
        <CardDescription>
          {rows.length === 1
            ? "Personas mode: every simulated worker shares one source IP."
            : rows.length
              ? `Showing up to ${rows.length} source addresses.`
              : "Waiting for the first query results..."}
        </CardDescription>
      </CardHeader>
      <CardContent className="px-0">
        <div className="max-h-96 overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <TableHead className="pl-4">Client IP</TableHead>
                <TableHead className="text-right">Queries</TableHead>
                <TableHead className="text-right">FP</TableHead>
                <TableHead className="text-right">FN</TableHead>
                <TableHead className="pr-4 text-right">Timeout</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.slice(0, MAX_TABLE_ROWS).map((row) => (
                <TableRow key={row.client_ip}>
                  <TableCell className="pl-4 font-mono">
                    {row.client_ip}
                  </TableCell>
                  <TableCell className="text-right font-mono num">
                    {fmtInt(row.count)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Count value={num(row.fp)} tone="font-semibold text-fp" />
                  </TableCell>
                  <TableCell className="text-right">
                    <Count value={num(row.fn)} tone="font-semibold text-fn" />
                  </TableCell>
                  <TableCell className="pr-4 text-right">
                    <Count value={num(row.timeout)} tone="text-warn" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  )
}
