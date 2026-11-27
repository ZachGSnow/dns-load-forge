import {
  ActivityIcon,
  DatabaseIcon,
  GaugeIcon,
  GitCompareArrowsIcon,
  InfoIcon,
  ListChecksIcon,
  RadarIcon,
} from "lucide-react"
import type * as React from "react"

import { AboutDialog } from "@/components/about-dialog"
import { RunStateBadge, VerdictBadge } from "@/components/status"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar"
import type { Route } from "@/hooks/use-route"
import { useLive } from "@/lib/live"

export const NAV: {
  route: Route
  label: string
  description: string
  icon: React.ElementType
}[] = [
  {
    route: "live",
    label: "Live run",
    description: "Throughput, verdict and findings for the run in progress",
    icon: ActivityIcon,
  },
  {
    route: "compare",
    label: "Compare",
    description: "Identical seeded traffic sent to each target in turn",
    icon: GitCompareArrowsIcon,
  },
  {
    route: "capacity",
    label: "Capacity",
    description: "The highest rate a target sustains within your limits",
    icon: GaugeIcon,
  },
  {
    route: "checks",
    label: "Checks",
    description: "Identity, bypass, encrypted DNS, DNSSEC and SafeSearch",
    icon: ListChecksIcon,
  },
  {
    route: "lists",
    label: "Domain lists",
    description: "The catalogue each run draws from, and its sources",
    icon: DatabaseIcon,
  },
]

export function AppSidebar({
  route,
  onNavigate,
  ...props
}: React.ComponentProps<typeof Sidebar> & {
  route: Route
  onNavigate: (route: Route) => void
}) {
  const { snapshot } = useLive()
  const run = snapshot?.run
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              onClick={() => onNavigate("live")}
              tooltip="DNS Load Forge"
            >
              <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                <RadarIcon className="size-4" />
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-semibold">DNS Load Forge</span>
                <span className="truncate text-xs text-muted-foreground">
                  DNS filter testing
                </span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Test</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map((item) => (
                <SidebarMenuItem key={item.route}>
                  <SidebarMenuButton
                    isActive={route === item.route}
                    tooltip={item.label}
                    onClick={() => onNavigate(item.route)}
                  >
                    <item.icon />
                    <span>{item.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <div className="flex flex-col gap-2 rounded-lg border bg-background/40 p-3 text-xs group-data-[collapsible=icon]:hidden">
          <div className="flex items-center justify-between gap-2">
            <span className="text-muted-foreground">Target</span>
            <RunStateBadge state={run?.state} />
          </div>
          <div
            className="truncate font-medium"
            title={run?.target_name || run?.server}
          >
            {run?.target_name || run?.server || "-"}
          </div>
          {run?.server && run?.target_name ? (
            <div className="truncate font-mono text-muted-foreground">
              {run.server}
            </div>
          ) : null}
          <VerdictBadge status={snapshot?.verdict?.status} />
        </div>
        <SidebarMenu>
          <SidebarMenuItem>
            <AboutDialog>
              <SidebarMenuButton tooltip="About">
                <InfoIcon />
                <span>About</span>
              </SidebarMenuButton>
            </AboutDialog>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
