// Every theme must keep text readable: body text, secondary text and every
// status colour at least 4.5:1 (WCAG AA for small text) against both the page
// background and the card surface, which is where tables and numbers sit.

import { readFileSync } from "node:fs"
import { resolve } from "node:path"

import { describe, expect, it } from "vitest"

import { THEMES } from "@/lib/themes"

const css = readFileSync(resolve(import.meta.dirname, "../index.css"), "utf8")

function block(selector: string): Record<string, string> {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const match = new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`).exec(css)
  if (!match) throw new Error(`no CSS block for ${selector}`)
  const tokens: Record<string, string> = {}
  for (const line of match[1].split(";")) {
    const decl = /--([\w-]+)\s*:\s*(.+)/.exec(line.trim())
    if (decl) tokens[decl[1]] = decl[2].trim()
  }
  return tokens
}

function luminance(hex: string): number {
  const m = /^#([0-9a-f]{6})$/i.exec(hex)
  if (!m) throw new Error(`not a #rrggbb colour: ${hex}`)
  const n = Number.parseInt(m[1], 16)
  const channel = (value: number) => {
    const c = value / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  const r = channel((n >> 16) & 255)
  const g = channel((n >> 8) & 255)
  const b = channel(n & 255)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

const light = block(":root")
const dark = { ...light, ...block(".dark") }

function tokensFor(id: string): Record<string, string> {
  if (id === "light") return light
  if (id === "dark" || id === "system") return dark
  return { ...dark, ...block(`.dark[data-theme="${id}"]`) }
}

const TEXT = [
  "foreground",
  "muted-foreground",
  "ok",
  "warn",
  "bad",
  "info",
  "fp",
  "fn",
]
const SURFACES = ["background", "card"]

describe("theme contrast", () => {
  for (const theme of THEMES.filter((t) => t.id !== "system")) {
    const tokens = tokensFor(theme.id)
    for (const text of TEXT) {
      for (const surface of SURFACES) {
        it(`${theme.label}: ${text} on ${surface} is at least 4.5:1`, () => {
          const ratio = contrast(tokens[text], tokens[surface])
          expect(
            ratio,
            `${tokens[text]} on ${tokens[surface]}`
          ).toBeGreaterThanOrEqual(4.5)
        })
      }
    }
    it(`${theme.label}: primary buttons are readable`, () => {
      expect(
        contrast(tokens["primary-foreground"], tokens.primary)
      ).toBeGreaterThanOrEqual(4.5)
    })
  }

  it("every palette in the picker has a CSS block", () => {
    for (const theme of THEMES.filter((t) => t.palette)) {
      expect(() => block(`.dark[data-theme="${theme.id}"]`)).not.toThrow()
    }
  })
})
