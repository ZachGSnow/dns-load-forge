import { describe, expect, it } from "vitest"

import {
  fmtAge,
  fmtDuration,
  fmtFraction,
  fmtInt,
  fmtMs,
  fmtRate,
  num,
  relTime,
} from "@/lib/format"
import { categoryRows, headline } from "@/lib/snapshot"

describe("format", () => {
  it("treats missing and non-finite values as zero", () => {
    expect(num(undefined)).toBe(0)
    expect(num(Number.NaN)).toBe(0)
    expect(num(null, 7)).toBe(7)
    expect(fmtInt(Number.POSITIVE_INFINITY)).toBe("0")
  })

  it("formats rates like the original dashboard", () => {
    expect(fmtRate(12345)).toBe("12,345")
    expect(fmtRate(250)).toBe("250")
    expect(fmtRate(42.25)).toBe("42.3")
    expect(fmtRate(3.14159)).toBe("3.14")
    expect(fmtRate(0)).toBe("0")
  })

  it("formats latency", () => {
    expect(fmtMs(0)).toBe("0")
    expect(fmtMs(4.44)).toBe("4.4")
    expect(fmtMs(42.4)).toBe("42")
    expect(fmtMs(1500)).toBe("1,500")
  })

  it("reports a missing ratio as a dash, not 0%", () => {
    expect(fmtFraction(null)).toBe("-")
    expect(fmtFraction(0.9714)).toBe("97.1%")
  })

  it("formats durations and ages", () => {
    expect(fmtDuration(3725)).toBe("01:02:05")
    expect(fmtAge(null)).toBe("never")
    expect(fmtAge(30)).toBe("just now")
    expect(fmtAge(7200)).toBe("2 h ago")
    expect(relTime(100, 130)).toBe("30s ago")
  })
})

describe("snapshot", () => {
  it("always yields the nine categories in display order", () => {
    const rows = categoryRows({
      by_category: [{ category: "block_ads", sent: 5, expect: "block" }],
    })
    expect(rows.map((r) => r.category)).toEqual([
      "allow_popular",
      "allow_longtail",
      "enterprise",
      "borderline",
      "block_ads",
      "block_malware",
      "block_phishing",
      "block_adult",
      "nxdomain_probe",
    ])
    expect(rows[4].sent).toBe(5)
    expect(rows[0].sent).toBe(0)
  })

  it("computes block and false-block rates the way compare.summarise_run does", () => {
    const lead = headline({
      by_category: [
        { category: "block_ads", expect: "block", blocked: 97, fn: 3 },
        { category: "allow_popular", expect: "allow", allowed: 999, fp: 1 },
        { category: "borderline", expect: "unknown", blocked: 50, fp: 0 },
      ],
    })
    expect(lead.blockRate).toBeCloseTo(0.97)
    expect(lead.falseBlockRate).toBeCloseTo(0.001)
    expect(headline({}).blockRate).toBeNull()
  })
})
