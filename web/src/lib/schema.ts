// The data contract with the Python server.  Mirrors the STATS SNAPSHOT SCHEMA
// at the bottom of src/dnsloadforge/spec.py; every field the dashboard reads is
// declared here.  The server can be older or newer than this page, so every
// field is optional and read through the normalisers in ./snapshot.ts.

export type RunState = "idle" | "starting" | "running" | "stopping" | "stopped"

export type VerdictStatus =
  "idle" | "unknown" | "passthrough" | "filtering" | "degraded" | "baseline"

export type Expectation = "allow" | "block" | "unknown" | "nxdomain"

export interface RunInfo {
  state?: RunState
  started_at?: number
  elapsed_s?: number
  server?: string
  target_name?: string
  mode?: "personas" | "pool"
  personas?: number
  source_ips?: number
  target_qps?: number
  seed?: number
  note?: string
  plan_index?: number
  plan_total?: number
  plan_targets?: string[]
  record_log?: string
  transport?: string
}

export interface Totals {
  sent?: number
  received?: number
  timeouts?: number
  errors?: number
  dropped?: number
  intended?: number
  completed?: number
  bytes_sent?: number
  bytes_received?: number
  unique_clients?: number
  unique_domains?: number
  domains_tracked?: number
}

export interface Rates {
  qps_sent?: number
  qps_recv?: number
  qps_sent_avg?: number
  qps_recv_avg?: number
  qps_completed_avg?: number
  error_pct?: number
  window_error_pct?: number
  dropped_pct?: number
  in_flight?: number
}

export interface Latency {
  p50?: number
  p95?: number
  p99?: number
  min?: number
  max?: number
  avg?: number
  run_p50?: number
  run_p95?: number
  run_p99?: number
  samples?: number
}

export interface SeriesPoint {
  t: number
  sent: number
  recv: number
  timeout: number
  fp: number
  fn: number
  p95: number
}

export interface CategoryRow {
  category: string
  label?: string
  expect?: Expectation
  sent?: number
  blocked?: number
  allowed?: number
  fp?: number
  fn?: number
  timeout?: number
  nxdomain?: number
  p95?: number
  pass_rate?: number | null
}

export interface DomainRow {
  qname: string
  count?: number
  category?: string
  outcome?: string
  p95?: number
}

export interface ClientRow {
  client_ip: string
  count?: number
  fp?: number
  fn?: number
  timeout?: number
}

export interface FindingRow {
  qname: string
  client_ip?: string
  category?: string
  rcode?: string
  answer?: string
  count?: number
  last_seen?: number
}

export interface Verdict {
  status?: VerdictStatus
  note?: string
}

export interface Snapshot {
  run?: RunInfo
  totals?: Totals
  rates?: Rates
  latency_ms?: Latency
  outcomes?: Record<string, number>
  rcodes?: Record<string, number>
  series?: SeriesPoint[]
  by_category?: CategoryRow[]
  top_domains?: DomainRow[]
  top_clients?: ClientRow[]
  false_positives?: FindingRow[]
  false_negatives?: FindingRow[]
  verdict?: Verdict
}

export interface Target {
  name: string
  server: string
  port?: number
  kind?: "appliance" | "public"
  blocks?: string[]
  sinkhole_ips?: string[]
  sinkhole_cidrs?: string[]
  notes?: string
  builtin?: boolean
}

export interface TargetsPayload {
  targets?: Target[]
  active?: string
  server?: string
}

export interface HistoryRun {
  index: number
  target: string
  server?: string
  finished_at?: number
  seed?: number
  personas?: number
  target_qps?: number
  elapsed_s?: number
  verdict?: VerdictStatus
  note?: string
  sent?: number
  received?: number
  timeouts?: number
  achieved_qps?: number
  error_pct?: number
  latency_ms?: { p50?: number; p95?: number; p99?: number }
  block_rate?: number | null
  false_block_rate?: number | null
  blocked?: number
  leaked?: number
  false_positives?: number
}

export interface HistoryPayload {
  runs?: HistoryRun[]
}

export interface ListCategory {
  category?: string
  label?: string
  count?: number
  source?: string
}

export interface ListsPayload {
  categories?: ListCategory[]
  cache_dir?: string
  fetched_at?: number
  offline?: boolean
  total?: number
}

export interface SourceRow {
  slug: string
  category?: string
  description?: string
  url?: string
  count?: number
  age_s?: number | null
  stale?: boolean
  enabled?: boolean
}

export interface SourceJobResult {
  slug?: string
  status?: string
  error?: string
}

export interface SourceJob {
  kind?: string
  state?: "idle" | "running" | "done" | "error"
  total?: number
  done?: number
  current?: string
  results?: SourceJobResult[]
  error?: string
}

export interface SourcesPayload {
  ok?: boolean
  error?: string
  sources?: SourceRow[]
  job?: SourceJob
  available?: boolean
  categories?: ListCategory[]
  total?: number
}

export interface ConfigPayload {
  server?: string
  port?: number
  target?: string
  mode?: string
  personas?: number
  target_qps?: number
  duration_s?: number
  timeout_s?: number
  seed?: number
  threads?: number
  max_inflight?: number
  qps_burst?: number
  source_ips?: string[]
  state?: RunState
  version?: string
}

export interface ControlResponse {
  ok?: boolean
  state?: RunState
  message?: string
  error?: string
}
