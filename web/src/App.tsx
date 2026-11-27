import { TriangleAlertIcon } from "lucide-react"

import { AppSidebar } from "@/components/app-sidebar"
import { RunProvider } from "@/components/run-context"
import { SiteHeader } from "@/components/site-header"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { useRoute } from "@/hooks/use-route"
import { DEMO } from "@/lib/api"
import { CapacityPage } from "@/pages/capacity"
import { ChecksPage } from "@/pages/checks"
import { ComparePage } from "@/pages/compare"
import { ListsPage } from "@/pages/lists"
import { LivePage } from "@/pages/live"

export function App() {
  const [route, navigate] = useRoute()
  return (
    <TooltipProvider delayDuration={200}>
      <RunProvider>
        <SidebarProvider>
          <AppSidebar route={route} onNavigate={navigate} />
          <SidebarInset className="min-w-0">
            <SiteHeader route={route} onNavigate={navigate} />
            {DEMO ? (
              <div className="flex items-center gap-2 border-b bg-warn/10 px-4 py-2 text-xs text-warn lg:px-6">
                <TriangleAlertIcon className="size-3.5" />
                Demo data generated in the page. No backend is contacted and the
                controls are inert.
              </div>
            ) : null}
            <main className="@container/main mx-auto flex w-full max-w-[1800px] min-w-0 flex-1 flex-col p-4 lg:p-6">
              {route === "compare" ? (
                <ComparePage />
              ) : route === "capacity" ? (
                <CapacityPage />
              ) : route === "checks" ? (
                <ChecksPage />
              ) : route === "lists" ? (
                <ListsPage />
              ) : (
                <LivePage />
              )}
            </main>
          </SidebarInset>
        </SidebarProvider>
        <Toaster position="bottom-right" richColors closeButton />
      </RunProvider>
    </TooltipProvider>
  )
}
