// Number and time formatting.  Every value from the server may be missing or
// non-finite (the server nulls Infinity and NaN), so each helper takes unknown.

export function num(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback
}

export function fmtInt(value: unknown): string {
  return Math.round(num(value)).toLocaleString("en-US")
}

/** Queries per second: whole numbers once they are big, a decimal below 100. */
export function fmtRate(value: unknown): string {
  const n = num(value)
  if (Math.abs(n) >= 1000) return fmtInt(n)
  if (Math.abs(n) >= 100) return n.toFixed(0)
  if (n === 0) return "0"
  return n.toFixed(n < 10 ? 2 : 1)
}

export function fmtMs(value: unknown): string {
  const n = num(value)
  if (n <= 0) return "0"
  if (n < 10) return n.toFixed(1)
  if (n < 100) return n.toFixed(0)
  return fmtInt(n)
}

/** A value that is already a percentage (5.0 means 5%). */
export function fmtPct(value: unknown, digits = 1): string {
  return `${num(value).toFixed(digits)}%`
}

/** A fraction (0.05 means 5%); null when there is nothing to divide. */
export function fmtFraction(value: unknown, digits = 1): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-"
  return `${(value * 100).toFixed(digits)}%`
}

export function fmtBytes(value: unknown): string {
  let n = num(value)
  const units = ["B", "KB", "MB", "GB", "TB"]
  let unit = 0
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024
    unit += 1
  }
  return `${unit === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[unit]}`
}

export function fmtDuration(seconds: unknown): string {
  const s = Math.max(0, Math.floor(num(seconds)))
  const hh = Math.floor(s / 3600)
  const mm = Math.floor((s % 3600) / 60)
  const ss = s % 60
  return [hh, mm, ss].map((v) => String(v).padStart(2, "0")).join(":")
}

/** HH:MM:SS of an epoch timestamp, in local time. */
export function clockOf(epochSeconds: unknown): string {
  const t = num(epochSeconds)
  if (t <= 0) return "-"
  const d = new Date(t * 1000)
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((v) => String(v).padStart(2, "0"))
    .join(":")
}

export function relTime(
  epochSeconds: unknown,
  now = Date.now() / 1000
): string {
  const t = num(epochSeconds)
  if (t <= 0) return "-"
  const d = now - t
  if (d < 0) return "just now"
  if (d < 1.5) return "just now"
  if (d < 60) return `${Math.round(d)}s ago`
  if (d < 3600) return `${Math.floor(d / 60)}m ${Math.round(d % 60)}s ago`
  if (d < 86400)
    return `${Math.floor(d / 3600)}h ${Math.floor((d % 3600) / 60)}m ago`
  return `${Math.floor(d / 86400)}d ago`
}

/** Age in seconds, as the domain-list table shows it. */
export function fmtAge(seconds: unknown): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return "never"
  if (seconds < 90) return "just now"
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`
  return `${Math.round(seconds / 86400)} d ago`
}

export function fmtDateTime(epochSeconds: unknown): string {
  const t = num(epochSeconds)
  if (t <= 0) return "-"
  const d = new Date(t * 1000)
  const pad = (v: number) => String(v).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}`
}
