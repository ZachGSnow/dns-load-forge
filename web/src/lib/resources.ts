import { DEMO, getJSON, postJSON } from "@/lib/api"
import {
  demoCapacity,
  demoChecks,
  demoConfig,
  demoHistory,
  demoLists,
  demoSources,
  demoTargets,
} from "@/lib/demo"
import type {
  CapacityPayload,
  CapacityPlan,
  CapacitySlo,
  ChecksPayload,
  ConfigPayload,
  ControlResponse,
  HistoryPayload,
  ListsPayload,
  SourcesPayload,
  TargetsPayload,
} from "@/lib/schema"

const demo = <T>(value: T) => Promise.resolve(value)

export const fetchTargets = () =>
  DEMO ? demo(demoTargets) : getJSON<TargetsPayload>("/api/targets")
export const fetchHistory = () =>
  DEMO ? demo(demoHistory) : getJSON<HistoryPayload>("/api/history")
export const fetchLists = () =>
  DEMO ? demo(demoLists) : getJSON<ListsPayload>("/api/lists")
export const fetchSources = () =>
  DEMO ? demo(demoSources) : getJSON<SourcesPayload>("/api/sources")
export const fetchChecks = () =>
  DEMO ? demo(demoChecks) : getJSON<ChecksPayload>("/api/checks")
export const fetchConfig = () =>
  DEMO ? demo(demoConfig) : getJSON<ConfigPayload>("/api/config")
export const fetchCapacity = () =>
  DEMO ? demo(demoCapacity) : getJSON<CapacityPayload>("/api/capacity")

export interface StartOptions {
  target?: string
  targets?: string[]
  target_qps?: number
  duration_s?: number
}

export interface ActionResult {
  ok: boolean
  message: string
}

function describe(
  action: string,
  result: {
    ok: boolean
    data: (ControlResponse & { message?: string }) | null
    error?: string
  }
): ActionResult {
  const data = result.data
  const ok = result.ok && data?.ok !== false
  const message =
    data?.message ||
    data?.error ||
    result.error ||
    `${action} ${ok ? "accepted" : "failed"}`
  return { ok, message: String(message) }
}

const DEMO_RESULT: ActionResult = {
  ok: false,
  message: "Demo mode: controls are inert and no backend is contacted.",
}

export async function startRun(options: StartOptions): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  const action =
    options.targets && options.targets.length > 1 ? "compare" : "start"
  const result = await postJSON<ControlResponse>("/api/control", {
    action,
    ...options,
  })
  return describe(action, result)
}

export async function stopRun(): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  return describe(
    "stop",
    await postJSON<ControlResponse>("/api/control", { action: "stop" })
  )
}

export async function refreshSources(slugs?: string[]): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  const body = slugs && slugs.length ? { slugs } : {}
  return describe(
    "refresh",
    await postJSON<ControlResponse>("/api/sources/refresh", body)
  )
}

export async function setSourceEnabled(
  slug: string,
  enabled: boolean
): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  return describe(
    enabled ? "enable" : "disable",
    await postJSON<ControlResponse>("/api/sources/enabled", { slug, enabled })
  )
}

export async function clearHistory(): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  return describe(
    "clear",
    await postJSON<ControlResponse>("/api/history/clear", {})
  )
}

export async function startCapacity(
  options: CapacityPlan & { target?: string; slo: CapacitySlo }
): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  return describe(
    "capacity",
    await postJSON<ControlResponse>("/api/control", {
      action: "capacity",
      ...options,
    })
  )
}

export async function runChecks(
  target: string | undefined,
  network: boolean
): Promise<ActionResult> {
  if (DEMO) return DEMO_RESULT
  return describe(
    "checks",
    await postJSON<ControlResponse>("/api/checks/run", { target, network })
  )
}
