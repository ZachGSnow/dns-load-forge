import { PlayIcon, SquareIcon } from "lucide-react"

import { NAV } from "@/components/app-sidebar"
import { CommandMenu } from "@/components/command-menu"
import { useRun } from "@/components/run-context"
import { ConnectionBadge, RunStateBadge } from "@/components/status"
import { ThemeMenu } from "@/components/theme-menu"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { Spinner } from "@/components/ui/spinner"
import type { Route } from "@/hooks/use-route"
import { DEMO } from "@/lib/api"
import { useLive } from "@/lib/live"

export function SiteHeader({
  route,
  onNavigate,
}: {
  route: Route
  onNavigate: (route: Route) => void
}) {
  const { snapshot, connection } = useLive()
  const run = useRun()
  const page = NAV.find((item) => item.route === route) ?? NAV[0]
  const state = snapshot?.run?.state ?? "idle"
  const stopping = state === "stopping"

  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70">
      <div className="flex w-full items-center gap-2 px-4 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator
          orientation="vertical"
          className="mx-1 data-[orientation=vertical]:h-4"
        />
        <div className="flex min-w-0 flex-col">
          <h1 className="truncate text-sm font-semibold">{page.label}</h1>
          <p className="hidden truncate text-xs text-muted-foreground lg:block">
            {page.description}
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <div className="hidden items-center gap-2 sm:flex">
            <RunStateBadge state={state} />
            <ConnectionBadge connection={connection} />
          </div>
          <CommandMenu onNavigate={onNavigate} />
          <ThemeMenu />
          {run.running || stopping ? (
            <Button
              variant="destructive"
              size="sm"
              disabled={run.busy || stopping || DEMO}
              onClick={() => void run.stop()}
            >
              {run.busy || stopping ? <Spinner /> : <SquareIcon />}
              Stop
            </Button>
          ) : (
            <Button
              size="sm"
              disabled={run.busy || DEMO}
              onClick={() => void run.start()}
            >
              {run.busy ? <Spinner /> : <PlayIcon />}
              Start
            </Button>
          )}
        </div>
      </div>
    </header>
  )
}
