// Mirrors spec.py (Category, RCODE_BUCKETS, Outcome).  Display order is fixed
// here, not taken from the payload, so table rows never reorder as counts change.

export const CATEGORY_ORDER = [
  "allow_popular",
  "allow_longtail",
  "enterprise",
  "borderline",
  "block_ads",
  "block_malware",
  "block_phishing",
  "block_adult",
  "nxdomain_probe",
] as const

export const CATEGORY_LABELS: Record<string, string> = {
  allow_popular: "Allow - popular",
  allow_longtail: "Allow - long tail",
  enterprise: "Allow - enterprise/breakage",
  borderline: "Borderline - trackers/CDN",
  block_ads: "Block - ads",
  block_malware: "Block - malware",
  block_phishing: "Block - phishing",
  block_adult: "Block - adult",
  nxdomain_probe: "NXDOMAIN probe",
}

export const RCODE_BUCKETS = [
  "NOERROR",
  "NXDOMAIN",
  "REFUSED",
  "SERVFAIL",
  "FORMERR",
  "NOTIMP",
  "TIMEOUT",
  "ERROR",
] as const

/** Wire rcodes: a share of responses received. */
export const RECEIVED_RCODES = [
  "NOERROR",
  "NXDOMAIN",
  "REFUSED",
  "SERVFAIL",
  "FORMERR",
  "NOTIMP",
] as const

/** Sentinels for queries that never got an answer: a share of queries sent. */
export const SENTINEL_RCODES = ["TIMEOUT", "ERROR"] as const

export const OUTCOME_ORDER = [
  "allowed",
  "blocked",
  "false_positive",
  "false_negative",
  "nxdomain",
  "timeout",
  "error",
] as const

export type Outcome = (typeof OUTCOME_ORDER)[number]

export const OUTCOME_LABELS: Record<Outcome, string> = {
  allowed: "Allowed",
  blocked: "Blocked",
  false_positive: "False positive",
  false_negative: "False negative",
  nxdomain: "NXDOMAIN",
  timeout: "Timeout",
  error: "Error",
}

export const OUTCOME_HINTS: Record<Outcome, string> = {
  allowed: "Resolved as expected",
  blocked: "Blocked as expected",
  false_positive: "Allow-listed name that was blocked (an outage)",
  false_negative: "Block-listed name that resolved (a gap)",
  nxdomain: "NXDOMAIN where that is the right answer",
  timeout: "Never answered",
  error: "Malformed answer or socket error",
}

/** Text colour utility for each outcome. */
export const OUTCOME_TONE: Record<Outcome, string> = {
  allowed: "text-ok",
  blocked: "text-foreground",
  false_positive: "text-fp",
  false_negative: "text-fn",
  nxdomain: "text-muted-foreground",
  timeout: "text-warn",
  error: "text-bad",
}

/** Dot colour for each outcome in legends and bars. */
export const OUTCOME_DOT: Record<Outcome, string> = {
  allowed: "bg-ok",
  blocked: "bg-muted-foreground",
  false_positive: "bg-fp",
  false_negative: "bg-fn",
  nxdomain: "bg-muted-foreground/50",
  timeout: "bg-warn",
  error: "bg-bad",
}

export const MAX_TABLE_ROWS = 25

/** Below this many completed queries the server keeps the verdict "unknown". */
export const MIN_VERDICT_SAMPLE = 200
