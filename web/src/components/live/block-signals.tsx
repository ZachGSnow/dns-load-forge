import { InfoIcon } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { fmtInt, fmtPct, num } from "@/lib/format"
import type { Snapshot } from "@/lib/schema"
import { signalRows } from "@/lib/signals"

function Section({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {title}
      </p>
      {children}
    </div>
  )
}

export function BlockSignalsCard({ snapshot }: { snapshot: Snapshot | null }) {
  const { rows, total } = signalRows(snapshot?.block_signals)
  const ede = snapshot?.ede ?? []
  const nsid = snapshot?.nsid ?? []
  return (
    <Card>
      <CardHeader>
        <CardTitle>How the target signals a block</CardTitle>
        <CardDescription>
          What blocked queries came back as, which decides what users see, and
          the Extended DNS Errors (RFC 8914) the filter used to say it blocked.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6 @2xl/main:grid-cols-3">
        <Section title={`Blocked answers (${fmtInt(total)})`}>
          {rows.length ? (
            <ul className="flex flex-col gap-2.5">
              {rows.map((row) => (
                <li
                  key={row.key}
                  className="flex flex-col gap-1"
                  title={row.hint}
                >
                  <div className="flex items-center justify-between gap-3 text-sm">
                    <span>{row.label}</span>
                    <span className="font-mono text-muted-foreground num">
                      {fmtInt(row.count)}
                      <span className="ml-2 inline-block w-12 text-right">
                        {fmtPct(row.share * 100)}
                      </span>
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                    <div
                      className={
                        row.key === "address"
                          ? "h-full rounded-full bg-warn"
                          : "h-full rounded-full bg-info"
                      }
                      style={{ width: `${(row.share * 100).toFixed(2)}%` }}
                    />
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">
              Nothing has been blocked yet.
            </p>
          )}
        </Section>
        <Section title="Extended DNS Errors">
          {ede.length ? (
            <div className="flex flex-wrap gap-2">
              {ede.map((row) => (
                <Badge
                  key={row.code}
                  variant="outline"
                  className="gap-2 font-mono font-normal"
                >
                  {row.code} {row.name}
                  <span className="text-muted-foreground num">
                    {fmtInt(row.count)}
                  </span>
                </Badge>
              ))}
            </div>
          ) : (
            <p className="flex gap-2 text-sm text-muted-foreground">
              <InfoIcon className="mt-0.5 size-4 shrink-0" />
              {total > 0
                ? "None: this target does not say when it blocks, so a block page it uses must be listed in its settings to be recognised."
                : "None seen yet."}
            </p>
          )}
        </Section>
        <Section title="Answering servers (NSID)">
          {nsid.length ? (
            <div className="flex flex-wrap gap-2">
              {nsid.map((row) => (
                <Badge
                  key={row.id}
                  variant="outline"
                  className="gap-2 font-mono font-normal"
                >
                  {row.id}
                  <span className="text-muted-foreground num">
                    {fmtInt(num(row.count))}
                  </span>
                </Badge>
              ))}
            </div>
          ) : (
            <p className="flex gap-2 text-sm text-muted-foreground">
              <InfoIcon className="mt-0.5 size-4 shrink-0" />
              Start the run with --nsid to see which server instances answered:
              an HA pair, an anycast site, or a resolver you did not expect.
            </p>
          )}
        </Section>
      </CardContent>
    </Card>
  )
}
