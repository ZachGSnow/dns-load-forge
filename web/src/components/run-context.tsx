import * as React from "react"
import { toast } from "sonner"

import { usePoll } from "@/hooks/use-poll"
import { live, useLive } from "@/lib/live"
import {
  fetchConfig,
  fetchTargets,
  startRun,
  stopRun,
  type ActionResult,
  type StartOptions,
} from "@/lib/resources"
import type { ConfigPayload, Target } from "@/lib/schema"

interface RunContextValue {
  targets: Target[]
  config: ConfigPayload | null
  target: string
  setTarget: (name: string) => void
  qps: string
  setQps: (value: string) => void
  duration: string
  setDuration: (value: string) => void
  running: boolean
  busy: boolean
  start: (extra?: StartOptions) => Promise<ActionResult>
  stop: () => Promise<ActionResult>
  refreshTargets: () => Promise<void>
}

const RunContext = React.createContext<RunContextValue | undefined>(undefined)

function parsePositive(value: string): number | undefined {
  const n = Number.parseFloat(value)
  return Number.isFinite(n) && n > 0 ? n : undefined
}

function parseDuration(value: string): number | undefined {
  const n = Number.parseFloat(value)
  return Number.isFinite(n) && n >= 0 ? n : undefined
}

/**
 * The settings for the next run (target, rate, duration), shared by the header's
 * Start button and the Live page's form so they can never disagree.
 */
export function RunProvider({ children }: { children: React.ReactNode }) {
  const { snapshot } = useLive()
  const { data: targetsPayload, refresh: refreshTargets } = usePoll(
    fetchTargets,
    30000
  )
  const { data: config } = usePoll(fetchConfig, 0)
  // What the operator typed, or null for "use the server's value".
  const [chosenTarget, setTarget] = React.useState("")
  const [qpsInput, setQps] = React.useState<string | null>(null)
  const [durationInput, setDuration] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)

  const targets = React.useMemo(
    () => targetsPayload?.targets ?? [],
    [targetsPayload]
  )
  const qps = qpsInput ?? (config ? String(config.target_qps ?? 1000) : "")
  const duration =
    durationInput ?? (config ? String(config.duration_s ?? 0) : "")
  const active = targetsPayload?.active
  const target = targets.some((t) => t.name === chosenTarget)
    ? chosenTarget
    : active && targets.some((t) => t.name === active)
      ? active
      : (targets[0]?.name ?? "")

  const running = snapshot?.run?.state === "running"

  const report = React.useCallback((result: ActionResult) => {
    if (result.ok) toast.success(result.message)
    else toast.error(result.message)
    void live.refresh()
    return result
  }, [])

  const start = React.useCallback(
    async (extra?: StartOptions) => {
      setBusy(true)
      try {
        const options: StartOptions = {
          target_qps: parsePositive(qps),
          duration_s: parseDuration(duration),
          ...extra,
        }
        if (!options.targets && !options.target && target)
          options.target = target
        return report(await startRun(options))
      } finally {
        setBusy(false)
      }
    },
    [duration, qps, report, target]
  )

  const stop = React.useCallback(async () => {
    setBusy(true)
    try {
      return report(await stopRun())
    } finally {
      setBusy(false)
    }
  }, [report])

  const value = React.useMemo<RunContextValue>(
    () => ({
      targets,
      config,
      target,
      setTarget,
      qps,
      setQps,
      duration,
      setDuration,
      running,
      busy,
      start,
      stop,
      refreshTargets,
    }),
    [
      targets,
      config,
      target,
      qps,
      duration,
      running,
      busy,
      start,
      stop,
      refreshTargets,
    ]
  )

  return <RunContext.Provider value={value}>{children}</RunContext.Provider>
}

export function useRun(): RunContextValue {
  const context = React.useContext(RunContext)
  if (!context) throw new Error("useRun must be used within a RunProvider")
  return context
}
