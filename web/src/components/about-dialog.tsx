import type * as React from "react"

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Separator } from "@/components/ui/separator"
import { usePoll } from "@/hooks/use-poll"
import { DEMO } from "@/lib/api"
import { fetchConfig } from "@/lib/resources"

export function AboutDialog({ children }: { children: React.ReactNode }) {
  const { data: config } = usePoll(fetchConfig, 0)
  return (
    <Dialog>
      <DialogTrigger asChild>{children}</DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>DNS Load Forge</DialogTitle>
          <DialogDescription>
            Vet a DNS filter with realistic office traffic, and compare filters
            like for like.
          </DialogDescription>
        </DialogHeader>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Version</dt>
          <dd className="font-mono">{config?.version ?? "-"}</dd>
          <dt className="text-muted-foreground">Dashboard</dt>
          <dd>
            One self-contained page; it makes no requests beyond this server.
          </dd>
        </dl>
        <Separator />
        <p className="text-sm text-muted-foreground">
          Only test infrastructure you own or are authorised to test. This tool
          sends real DNS traffic, including lookups of malware and phishing
          domains.
        </p>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
          <a
            className="text-primary underline-offset-4 hover:underline"
            href={DEMO ? "#" : "/api/licenses"}
            target="_blank"
            rel="noreferrer"
          >
            Open source licenses
          </a>
          <a
            className="text-primary underline-offset-4 hover:underline"
            href="https://github.com/ZachGSnow/dns-load-forge"
            target="_blank"
            rel="noreferrer"
          >
            Source and documentation
          </a>
        </div>
      </DialogContent>
    </Dialog>
  )
}
