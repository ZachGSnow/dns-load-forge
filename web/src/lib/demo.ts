// Demo mode (?demo=1): plausible data generated in the page, so the dashboard
// can be inspected, developed and screenshotted with no backend at all.  Names
// and addresses are documentation ranges (RFC 1918, RFC 5737) or the curated
// enterprise names the tool really sends.

import { CATEGORY_LABELS, CATEGORY_ORDER } from "@/lib/constants"
import type {
  ConfigPayload,
  FindingRow,
  HistoryPayload,
  ListsPayload,
  SeriesPoint,
  Snapshot,
  SourcesPayload,
  TargetsPayload,
} from "@/lib/schema"

const ENTERPRISE = [
  "login.microsoftonline.com",
  "outlook.office365.com",
  "teams.microsoft.com",
  "graph.windows.net",
]
const BLOCKED = [
  "ads.tracker-example.net",
  "doubleclick.example.com",
  "malware-c2.example.org",
]
const POPULAR = [
  "www.google.com",
  "cdn.jsdelivr.net",
  "graph.microsoft.com",
  "api.github.com",
  "www.amazon.com",
]

const SHARE: Record<string, number> = {
  allow_popular: 0.42,
  allow_longtail: 0.18,
  enterprise: 0.11,
  borderline: 0.07,
  block_ads: 0.09,
  block_malware: 0.04,
  block_phishing: 0.03,
  block_adult: 0.01,
  nxdomain_probe: 0.05,
}

export interface Demo {
  snapshot: () => Snapshot
}

export function createDemo(): Demo {
  const startedAt = Date.now() / 1000
  const series: SeriesPoint[] = []
  const fpMap = new Map<string, FindingRow>()
  const fnMap = new Map<string, FindingRow>()
  let tick = 0
  let totals = { sent: 0, received: 0, timeouts: 0, errors: 0, fp: 0, fn: 0 }

  function snapshot(): Snapshot {
    tick += 1
    const now = Date.now() / 1000
    // A false-positive burst between ticks 25 and 45 so the alert panels and
    // the DEGRADED verdict are exercised.
    const inBurst = tick >= 25 && tick <= 45
    const sent = 900 + Math.round(Math.sin(tick / 7) * 120 + Math.random() * 60)
    const fp = inBurst
      ? 18 + Math.round(Math.random() * 25)
      : Math.random() < 0.15
        ? 1
        : 0
    const fn = Math.random() < 0.3 ? Math.round(Math.random() * 3) : 0
    const timeout = Math.random() < 0.12 ? Math.round(Math.random() * 5) : 0
    const recv = sent - timeout
    const p95 = inBurst ? 60 + Math.random() * 90 : 4 + Math.random() * 8

    series.push({ t: Math.round(now), sent, recv, timeout, fp, fn, p95 })
    while (series.length > 300) series.shift()
    totals = {
      sent: totals.sent + sent,
      received: totals.received + recv,
      timeouts: totals.timeouts + timeout,
      errors: totals.errors + (Math.random() < 0.2 ? 1 : 0),
      fp: totals.fp + fp,
      fn: totals.fn + fn,
    }

    if (inBurst) {
      ENTERPRISE.forEach((qname, i) => {
        const row = fpMap.get(qname) ?? {
          qname,
          client_ip: "10.1.106.7",
          category: "enterprise",
          rcode: i % 2 ? "SERVFAIL" : "NXDOMAIN",
          count: 0,
          last_seen: 0,
        }
        row.count = (row.count ?? 0) + 1 + Math.round(Math.random() * 2)
        row.last_seen = now - Math.random() * 20
        fpMap.set(qname, row)
      })
    }
    if (fn > 0) {
      const qname = BLOCKED[tick % BLOCKED.length]
      const row = fnMap.get(qname) ?? {
        qname,
        client_ip: "10.1.106.7",
        category: "block_malware",
        answer: `203.0.113.${10 + (tick % 40)}`,
        count: 0,
        last_seen: 0,
      }
      row.count = (row.count ?? 0) + fn
      row.last_seen = now - Math.random() * 20
      fnMap.set(qname, row)
    }

    const byCategory = CATEGORY_ORDER.map((category) => {
      const share = SHARE[category] ?? 0.02
      const cSent = Math.round(totals.sent * share)
      const isAllow = category.startsWith("allow") || category === "enterprise"
      const expect =
        category === "borderline"
          ? ("unknown" as const)
          : category === "nxdomain_probe"
            ? ("nxdomain" as const)
            : isAllow
              ? ("allow" as const)
              : ("block" as const)
      const cFp = category === "enterprise" ? totals.fp : 0
      const cFn =
        expect === "block" ? Math.round(totals.fn * (share / 0.17)) : 0
      const cTimeout = Math.round(cSent * 0.002)
      const blocked =
        expect === "block" ? Math.max(0, cSent - cFn - cTimeout) : 0
      const allowed =
        expect === "allow" || expect === "unknown"
          ? Math.max(0, cSent - cFp - cTimeout)
          : 0
      const nxdomain = expect === "nxdomain" ? Math.max(0, cSent - cTimeout) : 0
      const completed = blocked + allowed + nxdomain + cFp + cFn + cTimeout
      return {
        category,
        label: CATEGORY_LABELS[category],
        expect,
        sent: cSent,
        blocked,
        allowed,
        nxdomain,
        fp: cFp,
        fn: cFn,
        timeout: cTimeout,
        p95: p95 + Math.random() * 3,
        pass_rate:
          completed > 0
            ? Math.max(0, 1 - (cFp + cFn + cTimeout) / completed)
            : 1,
      }
    })

    const topDomains = POPULAR.map((qname, i) => ({
      qname,
      count: tick * (40 - i * 5) + Math.round(Math.random() * 20),
      category: i < 3 ? "allow_popular" : "allow_longtail",
      outcome: "allowed",
      p95: 2 + Math.random() * 6,
    })).concat([
      {
        qname: "ads.tracker-example.net",
        count: tick * 18,
        category: "block_ads",
        outcome: "blocked",
        p95: 3 + Math.random() * 4,
      },
      {
        qname: "kq3vz9xm4pl2.invalid",
        count: tick * 6,
        category: "nxdomain_probe",
        outcome: "nxdomain",
        p95: 4 + Math.random() * 5,
      },
    ])
    if (inBurst) {
      topDomains.push({
        qname: ENTERPRISE[0],
        count: tick * 31,
        category: "enterprise",
        outcome: "false_positive",
        p95: 140,
      })
    }

    const status = inBurst ? "degraded" : tick < 6 ? "unknown" : "filtering"
    const blockedTotal = byCategory.reduce((sum, row) => sum + row.blocked, 0)
    const allowedTotal = byCategory.reduce((sum, row) => sum + row.allowed, 0)

    return {
      run: {
        state: "running",
        started_at: startedAt,
        elapsed_s: now - startedAt,
        server: "10.1.106.5:53",
        target_name: "Lab appliance",
        mode: "personas",
        personas: 10000,
        source_ips: 1,
        target_qps: 1000,
        seed: 1337,
      },
      totals: {
        sent: totals.sent,
        received: totals.received,
        timeouts: totals.timeouts,
        errors: totals.errors,
        dropped: 0,
        intended: totals.sent,
        completed: totals.received + totals.timeouts + totals.errors,
        bytes_sent: totals.sent * 42,
        bytes_received: totals.received * 118,
        unique_clients: 1,
        unique_domains: 4821 + tick * 37,
      },
      rates: {
        qps_sent: sent,
        qps_recv: recv,
        qps_sent_avg: 960,
        qps_recv_avg: 958,
        error_pct:
          totals.sent > 0
            ? (100 * (totals.timeouts + totals.errors)) / totals.sent
            : 0,
        window_error_pct: sent > 0 ? (100 * timeout) / sent : 0,
        dropped_pct: 0,
        in_flight: 12 + Math.round(Math.random() * 20),
      },
      latency_ms: {
        p50: p95 * 0.35,
        p95,
        p99: p95 * 1.8,
        min: 0.4,
        max: p95 * 4,
        avg: p95 * 0.55,
        run_p50: 2,
        run_p95: 9,
        run_p99: 20,
        samples: totals.received,
      },
      outcomes: {
        allowed: allowedTotal,
        blocked: blockedTotal,
        false_positive: totals.fp,
        false_negative: totals.fn,
        nxdomain: byCategory.reduce((sum, row) => sum + row.nxdomain, 0),
        timeout: totals.timeouts,
        error: totals.errors,
      },
      rcodes: {
        NOERROR: Math.round(totals.received * 0.82),
        NXDOMAIN: Math.round(totals.received * 0.17),
        REFUSED: inBurst ? 60 * tick : 4,
        SERVFAIL: inBurst ? 30 * tick : 1,
        FORMERR: 0,
        NOTIMP: 0,
        TIMEOUT: totals.timeouts,
        ERROR: totals.errors,
      },
      series: series.slice(),
      by_category: byCategory,
      top_domains: topDomains,
      top_clients: [
        {
          client_ip: "10.1.106.7",
          count: totals.sent,
          fp: totals.fp,
          fn: totals.fn,
          timeout: totals.timeouts,
        },
      ],
      false_positives: Array.from(fpMap.values()),
      false_negatives: Array.from(fnMap.values()),
      verdict: {
        status,
        note:
          status === "degraded"
            ? "Blocking legitimate traffic. Queries for allow-listed enterprise domains were refused or NXDOMAINed. See the false-positive table - this is what users report as outages."
            : status === "unknown"
              ? "Only a few queries completed; 200 are needed before any conclusion is trustworthy."
              : "Filtering correctly. Block-listed queries were refused and legitimate queries resolved, with no false positives.",
      },
    }
  }

  return { snapshot }
}

export const demoTargets: TargetsPayload = {
  active: "Lab appliance",
  server: "10.1.106.5:53",
  targets: [
    {
      name: "Lab appliance",
      server: "10.1.106.5",
      port: 53,
      kind: "appliance",
      notes: "The filter under test.",
    },
    {
      name: "Quad9",
      server: "9.9.9.9",
      port: 53,
      kind: "public",
      builtin: true,
      notes: "Quad9 blocks malicious domains with NXDOMAIN.",
    },
    {
      name: "Cloudflare Security",
      server: "1.1.1.2",
      port: 53,
      kind: "public",
      builtin: true,
      notes: "Blocks malware and phishing with 0.0.0.0.",
    },
    {
      name: "OpenDNS FamilyShield",
      server: "208.67.222.123",
      port: 53,
      kind: "public",
      builtin: true,
      notes: "Answers blocked names with a block-page address.",
    },
    {
      name: "Google Public DNS (unfiltered baseline)",
      server: "8.8.8.8",
      port: 53,
      kind: "public",
      builtin: true,
      blocks: [],
      notes: "No filtering. A baseline.",
    },
  ],
}

export const demoHistory: HistoryPayload = {
  runs: [
    {
      index: 1,
      target: "Lab appliance",
      server: "10.1.106.5:53",
      finished_at: Date.now() / 1000 - 900,
      verdict: "filtering",
      sent: 60120,
      achieved_qps: 1002,
      error_pct: 0.1,
      latency_ms: { p50: 2, p95: 9, p99: 20 },
      block_rate: 0.982,
      false_block_rate: 0,
      blocked: 10180,
      leaked: 186,
      false_positives: 0,
      note: "Filtering correctly.",
    },
    {
      index: 2,
      target: "Quad9",
      server: "9.9.9.9:53",
      finished_at: Date.now() / 1000 - 820,
      verdict: "degraded",
      sent: 6012,
      achieved_qps: 100,
      error_pct: 0.3,
      latency_ms: { p50: 14, p95: 30, p99: 50 },
      block_rate: 0.914,
      false_block_rate: 0.0004,
      blocked: 410,
      leaked: 39,
      false_positives: 2,
      note: "Blocking legitimate traffic.",
    },
    {
      index: 3,
      target: "Cloudflare Security",
      server: "1.1.1.2:53",
      finished_at: Date.now() / 1000 - 740,
      verdict: "filtering",
      sent: 6010,
      achieved_qps: 100,
      error_pct: 0.1,
      latency_ms: { p50: 9, p95: 20, p99: 30 },
      block_rate: 0.951,
      false_block_rate: 0,
      blocked: 427,
      leaked: 22,
      false_positives: 0,
      note: "Filtering correctly.",
    },
  ],
}

export const demoLists: ListsPayload = {
  cache_dir: "lists/cache (demo)",
  fetched_at: Date.now() / 1000 - 3600,
  offline: false,
  total: 1462000,
  categories: CATEGORY_ORDER.map((category, i) => ({
    category,
    label: CATEGORY_LABELS[category],
    count: [250000, 250000, 312, 41200, 72526, 98100, 61300, 250000, 0][i],
    source:
      category === "enterprise"
        ? "built-in"
        : category === "nxdomain_probe"
          ? "generated"
          : `demo source ${i + 1}`,
  })),
}

export const demoSources: SourcesPayload = {
  ok: true,
  available: true,
  job: { kind: "", state: "idle", results: [] },
  sources: [
    {
      slug: "umbrella-top-1m",
      category: "allow_popular",
      description: "Cisco Umbrella popularity list",
      count: 1000000,
      age_s: 7200,
      stale: false,
      enabled: true,
    },
    {
      slug: "tranco-top-1m",
      category: "allow_popular",
      description: "Tranco research ranking",
      count: 1000000,
      age_s: 7200,
      stale: false,
      enabled: true,
    },
    {
      slug: "majestic-million",
      category: "allow_longtail",
      description: "Majestic Million",
      count: 1000000,
      age_s: 7200,
      stale: false,
      enabled: true,
    },
    {
      slug: "blp-ads",
      category: "block_ads",
      description: "Block List Project - ads",
      count: 154000,
      age_s: 7200,
      stale: false,
      enabled: true,
    },
    {
      slug: "urlhaus",
      category: "block_malware",
      description: "abuse.ch URLhaus host file",
      count: 2100,
      age_s: 700000,
      stale: true,
      enabled: true,
    },
    {
      slug: "phishing-army",
      category: "block_phishing",
      description: "Phishing Army extended",
      count: 140000,
      age_s: 7200,
      stale: false,
      enabled: false,
    },
  ],
}

export const demoConfig: ConfigPayload = {
  server: "10.1.106.5",
  port: 53,
  target: "10.1.106.5:53",
  mode: "personas",
  personas: 10000,
  target_qps: 1000,
  duration_s: 300,
  timeout_s: 2,
  seed: 1337,
  threads: 1,
  max_inflight: 20000,
  qps_burst: 1,
  state: "running",
  version: "demo",
}
