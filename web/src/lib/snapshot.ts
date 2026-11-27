import { CATEGORY_LABELS, CATEGORY_ORDER } from "@/lib/constants"
import { num } from "@/lib/format"
import type {
  CategoryRow,
  Expectation,
  Snapshot,
  VerdictStatus,
} from "@/lib/schema"

export interface CategoryView {
  category: string
  label: string
  expect: Expectation
  sent: number
  blocked: number
  allowed: number
  fp: number
  fn: number
  timeout: number
  nxdomain: number
  p95: number
  passRate: number | null
}

/** All nine categories in their fixed display order, whatever the payload holds. */
export function categoryRows(snapshot: Snapshot | null): CategoryView[] {
  const index = new Map<string, CategoryRow>()
  for (const row of snapshot?.by_category ?? []) {
    if (row && row.category) index.set(String(row.category), row)
  }
  return CATEGORY_ORDER.map((category) => {
    const row = index.get(category)
    return {
      category,
      label: row?.label
        ? String(row.label)
        : (CATEGORY_LABELS[category] ?? category),
      expect: (row?.expect ?? "unknown") as Expectation,
      sent: num(row?.sent),
      blocked: num(row?.blocked),
      allowed: num(row?.allowed),
      fp: num(row?.fp),
      fn: num(row?.fn),
      timeout: num(row?.timeout),
      nxdomain: num(row?.nxdomain),
      p95: num(row?.p95),
      passRate:
        typeof row?.pass_rate === "number" && Number.isFinite(row.pass_rate)
          ? row.pass_rate
          : null,
    }
  })
}

export interface Headline {
  blocked: number
  leaked: number
  allowed: number
  harmed: number
  /** Share of expected-block queries that were blocked; null if none were sent. */
  blockRate: number | null
  /** Share of expected-allow queries wrongly blocked; null if none answered. */
  falseBlockRate: number | null
}

/** The same arithmetic as compare.summarise_run, so the cards match the table. */
export function headline(snapshot: Snapshot | null): Headline {
  let blocked = 0
  let leaked = 0
  let allowed = 0
  let harmed = 0
  for (const row of snapshot?.by_category ?? []) {
    if (row.expect === "block") {
      blocked += num(row.blocked)
      leaked += num(row.fn)
    } else if (row.expect === "allow") {
      allowed += num(row.allowed)
      harmed += num(row.fp)
    }
  }
  return {
    blocked,
    leaked,
    allowed,
    harmed,
    blockRate: blocked + leaked > 0 ? blocked / (blocked + leaked) : null,
    falseBlockRate: harmed + allowed > 0 ? harmed / (harmed + allowed) : null,
  }
}

export function verdictStatus(snapshot: Snapshot | null): VerdictStatus {
  return (snapshot?.verdict?.status ?? "idle") as VerdictStatus
}

export const DEFAULT_VERDICT_NOTES: Record<VerdictStatus, string> = {
  filtering:
    "Block-listed traffic is being blocked and allow-listed traffic is resolving.",
  baseline:
    "No categories are expected to be blocked for this target; measuring resolver behaviour only.",
  passthrough:
    "Block-listed domains are resolving - the filter is not applying policy to this traffic.",
  degraded: "Filtering is in place but something is wrong; the note says what.",
  idle: "No run has started yet. Pick a target and press Start.",
  unknown:
    "Not enough results yet to judge the target, or nothing block-listed was sent.",
}

/** Tone classes per verdict: accent border, tint, text and icon colour. */
export const VERDICT_TONE: Record<
  VerdictStatus,
  { text: string; border: string; tint: string; label: string }
> = {
  filtering: {
    text: "text-ok",
    border: "border-l-ok",
    tint: "bg-ok/5",
    label: "Filtering",
  },
  baseline: {
    text: "text-info",
    border: "border-l-info",
    tint: "bg-info/5",
    label: "Baseline",
  },
  passthrough: {
    text: "text-bad",
    border: "border-l-bad",
    tint: "bg-bad/8",
    label: "Passthrough",
  },
  degraded: {
    text: "text-warn",
    border: "border-l-warn",
    tint: "bg-warn/8",
    label: "Degraded",
  },
  unknown: {
    text: "text-muted-foreground",
    border: "border-l-muted-foreground/40",
    tint: "",
    label: "Unknown",
  },
  idle: {
    text: "text-muted-foreground",
    border: "border-l-muted-foreground/40",
    tint: "",
    label: "Idle",
  },
}
