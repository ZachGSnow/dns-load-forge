import {
  DownloadIcon,
  PaletteIcon,
  PlayIcon,
  SearchIcon,
  SquareIcon,
} from "lucide-react"
import * as React from "react"

import { NAV } from "@/components/app-sidebar"
import { useRun } from "@/components/run-context"
import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command"
import { Kbd } from "@/components/ui/kbd"
import type { Route } from "@/hooks/use-route"
import { DEMO, DOWNLOADS } from "@/lib/api"
import { THEMES } from "@/lib/themes"

/** Ctrl+K (or Cmd+K): jump to a page, start or stop a run, switch theme, export. */
export function CommandMenu({
  onNavigate,
}: {
  onNavigate: (route: Route) => void
}) {
  const [open, setOpen] = React.useState(false)
  const run = useRun()
  const { setTheme } = useTheme()

  React.useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault()
        setOpen((value) => !value)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  const act = (fn: () => void) => () => {
    setOpen(false)
    fn()
  }

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="hidden w-48 justify-between text-muted-foreground md:flex"
        onClick={() => setOpen(true)}
      >
        <span className="flex items-center gap-2">
          <SearchIcon />
          Commands
        </span>
        <Kbd>Ctrl K</Kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput placeholder="Type a command or search..." />
        <CommandList>
          <CommandEmpty>No matching command.</CommandEmpty>
          <CommandGroup heading="Run">
            <CommandItem
              disabled={run.running || run.busy}
              onSelect={act(() => void run.start())}
            >
              <PlayIcon />
              Start run{run.target ? ` against ${run.target}` : ""}
            </CommandItem>
            <CommandItem
              disabled={!run.running || run.busy}
              onSelect={act(() => void run.stop())}
            >
              <SquareIcon />
              Stop run
            </CommandItem>
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="Go to">
            {NAV.map((item) => (
              <CommandItem
                key={item.route}
                onSelect={act(() => onNavigate(item.route))}
              >
                <item.icon />
                {item.label}
                <CommandShortcut className="hidden sm:inline">
                  {item.description}
                </CommandShortcut>
              </CommandItem>
            ))}
          </CommandGroup>
          {!DEMO ? (
            <>
              <CommandSeparator />
              <CommandGroup heading="Export the per-query evidence">
                {(["csv", "jsonl", "json"] as const).map((format) => (
                  <CommandItem
                    key={format}
                    onSelect={act(() => {
                      window.location.href = DOWNLOADS[format]
                    })}
                  >
                    <DownloadIcon />
                    Download {format.toUpperCase()}
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          ) : null}
          <CommandSeparator />
          <CommandGroup heading="Theme">
            {THEMES.map((option) => (
              <CommandItem
                key={option.id}
                onSelect={act(() => setTheme(option.id))}
              >
                <PaletteIcon />
                {option.label}
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  )
}
