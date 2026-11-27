import { BlockSignalsCard } from "@/components/live/block-signals"
import { OutcomesCard, RcodeCard } from "@/components/live/breakdowns"
import { ConnectionsCard } from "@/components/live/connections"
import { KpiCards } from "@/components/live/kpi-cards"
import { LatencyCard } from "@/components/live/latency-card"
import { RunSetup } from "@/components/live/run-setup"
import {
  CategoryTable,
  FindingsCard,
  TopClients,
  TopDomains,
} from "@/components/live/tables"
import { TrafficChart } from "@/components/live/traffic-chart"
import { VerdictBanner } from "@/components/live/verdict-banner"
import { num } from "@/lib/format"
import { useLive } from "@/lib/live"

export function LivePage() {
  const { snapshot } = useLive()
  const series = snapshot?.series ?? []
  return (
    <div className="flex flex-col gap-4 lg:gap-6">
      <VerdictBanner snapshot={snapshot} />
      <RunSetup />
      <KpiCards snapshot={snapshot} />
      <ConnectionsCard snapshot={snapshot} />
      <div className="grid gap-4 lg:gap-6 @2xl/main:grid-cols-3">
        <TrafficChart series={series} />
        <OutcomesCard snapshot={snapshot} />
      </div>
      <div className="grid gap-4 lg:gap-6 @2xl/main:grid-cols-3">
        <LatencyCard latency={snapshot?.latency_ms ?? {}} series={series} />
        <RcodeCard snapshot={snapshot} />
      </div>
      <BlockSignalsCard snapshot={snapshot} />
      <CategoryTable snapshot={snapshot} />
      <div className="grid gap-4 xl:gap-6 @4xl/main:grid-cols-2">
        <FindingsCard kind="fp" rows={snapshot?.false_positives ?? []} />
        <FindingsCard kind="fn" rows={snapshot?.false_negatives ?? []} />
      </div>
      <div className="grid gap-4 lg:gap-6 @2xl/main:grid-cols-3">
        <TopDomains
          rows={snapshot?.top_domains ?? []}
          unique={num(snapshot?.totals?.unique_domains)}
        />
        <TopClients rows={snapshot?.top_clients ?? []} />
      </div>
    </div>
  )
}
