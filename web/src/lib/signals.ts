// How a filter signals a block (engine.BLOCK_SIGNALS), in display order, with what
// each one means for the person whose page did not load.

export const SIGNAL_ORDER = [
  "nxdomain",
  "refused",
  "sinkhole",
  "nodata",
  "address",
  "servfail",
  "other",
] as const

export const SIGNAL_LABELS: Record<string, string> = {
  nxdomain: "NXDOMAIN",
  refused: "REFUSED",
  sinkhole: "Sinkhole address",
  nodata: "No records",
  address: "Unlisted address",
  servfail: "SERVFAIL",
  other: "Other",
}

export const SIGNAL_HINTS: Record<string, string> = {
  nxdomain:
    "Says the name does not exist; the browser shows a not-found error.",
  refused: "Refuses to answer; the browser shows a DNS error.",
  sinkhole:
    "Answers with a null or block-page address this target is known to use.",
  nodata:
    "Answers with no records, usually for query types a block page cannot fill.",
  address:
    "Answers with an address the target's settings do not list; recognised only because the filter said so with an Extended DNS Error.",
  servfail: "Fails the query.",
  other: "Any other response code.",
}

export interface SignalRow {
  key: string
  label: string
  hint: string
  count: number
  share: number
}

export function signalRows(signals: Record<string, number> | undefined): {
  rows: SignalRow[]
  total: number
} {
  const source = signals ?? {}
  const total = Object.values(source).reduce(
    (sum, value) => sum + (Number.isFinite(value) ? value : 0),
    0
  )
  const keys = [
    ...SIGNAL_ORDER.filter((key) => (source[key] ?? 0) > 0),
    ...Object.keys(source).filter(
      (key) =>
        !(SIGNAL_ORDER as readonly string[]).includes(key) && source[key] > 0
    ),
  ]
  return {
    total,
    rows: keys.map((key) => ({
      key,
      label: SIGNAL_LABELS[key] ?? key,
      hint: SIGNAL_HINTS[key] ?? "",
      count: source[key] ?? 0,
      share: total > 0 ? (source[key] ?? 0) / total : 0,
    })),
  }
}

/** "NXDOMAIN 97%", the mechanism behind most of a run's blocks. */
export function dominantSignal(
  signals: Record<string, number> | undefined
): string {
  const { rows } = signalRows(signals)
  if (!rows.length) return "-"
  const top = rows.reduce((best, row) => (row.count > best.count ? row : best))
  return `${top.label} ${(top.share * 100).toFixed(0)}%`
}
