// The capacity search's ramp, mirrored from capacity.py so the form can say how
// many steps a search takes before it starts.  The rates themselves always come
// from the server.

/** Two significant figures (1,519 -> 1,500), as capacity.nice_rate does. */
export function niceRate(rate: number): number {
  if (rate < 10) return Math.max(1, Math.round(rate))
  const digits = Math.floor(Math.log10(rate)) - 1
  return Math.round(rate / 10 ** digits) * 10 ** digits
}

/** The rates the ramp tries if nothing fails, start to max. */
export function ramp(start: number, max: number, growth: number): number[] {
  if (!(start > 0) || !(max >= start) || !(growth > 1)) return []
  const rates: number[] = []
  for (let index = 0; index < 200; index += 1) {
    const rate = start * growth ** index
    if (rate >= max * 0.999) break
    const rounded = niceRate(rate)
    if (!rates.length || rounded > rates[rates.length - 1]) rates.push(rounded)
  }
  const top = Math.round(max)
  if (!rates.length || top > rates[rates.length - 1]) rates.push(top)
  return rates
}

/** The longest a search can take, in seconds: as CapacityPlan.estimate_s. */
export function estimateSeconds(
  start: number,
  max: number,
  growth: number,
  stepSeconds: number,
  refine: number
): number {
  const steps = ramp(start, max, growth).length + Math.max(0, refine)
  return steps * (stepSeconds + 2.5 + 2)
}
