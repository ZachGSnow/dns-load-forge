import { describe, expect, it } from "vitest"

import { estimateSeconds, niceRate, ramp } from "@/lib/capacity"

// The same cases as tests/test_capacity.py, so the form's estimate and the
// server's plan cannot drift apart.
describe("capacity ramp", () => {
  it("rounds rates to two significant figures", () => {
    expect([1519, 2278, 675, 99.6, 3.2].map(niceRate)).toEqual([
      1500, 2300, 680, 100, 3,
    ])
  })

  it("ramps from the start to the highest rate", () => {
    expect(ramp(200, 2000, 2)).toEqual([200, 400, 800, 1600, 2000])
    expect(ramp(500, 500, 1.5)).toEqual([500])
  })

  it("refuses a plan that cannot ramp", () => {
    expect(ramp(0, 100, 2)).toEqual([])
    expect(ramp(500, 100, 2)).toEqual([])
    expect(ramp(100, 500, 1)).toEqual([])
  })

  it("estimates the longest search", () => {
    // 5 ramp steps and 2 refinements, each 20s plus the drain and the pause.
    expect(estimateSeconds(200, 2000, 2, 20, 2)).toBe(7 * 24.5)
  })
})
