// Writes the license notices for every package bundled into the dashboard.
//
// The built page redistributes React, Radix, Recharts, the Geist fonts and the
// rest, so their notices have to travel with it.  This reads the modules whose
// code survived tree-shaking into the page, rather than package.json, so a
// dependency used only by the tooling does not appear and one pulled in
// transitively does.

import { existsSync, readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"

const LICENSE_FILE = /^(licen[cs]e|copying|notice)(\.(md|txt|markdown))?$/i

// Assets that enter the page through CSS rather than as modules.
const ALWAYS = [
  "@fontsource-variable/geist",
  "@fontsource-variable/geist-mono",
  "tailwindcss",
  "tw-animate-css",
  "shadcn",
]

// Typography that license files use, by code point, and its ASCII spelling.
const FOLD = new Map([
  [0xa9, "(c)"],
  [0xae, "(R)"],
  [0x2122, "(TM)"],
  [0x2018, "'"],
  [0x2019, "'"],
  [0x201c, '"'],
  [0x201d, '"'],
  [0x2013, "-"],
  [0x2014, "-"],
  [0x2026, "..."],
  [0xa0, " "],
])

/** The repository keeps every file plain ASCII (CONTRIBUTING.md), notices included. */
export function toAscii(text) {
  let out = ""
  for (const ch of text.replace(/\r\n?/g, "\n")) {
    const code = ch.codePointAt(0)
    if (code === 9 || code === 10 || (code >= 32 && code < 127)) {
      out += ch
      continue
    }
    const folded = FOLD.get(code)
    if (folded !== undefined) {
      out += folded
      continue
    }
    // Accented letters keep their base letter; anything else becomes "?".
    const base = ch.normalize("NFKD").replace(/[^\x20-\x7e]/g, "")
    out += base || "?"
  }
  return out
}

function packageOf(id) {
  const path = id.replace(/^\0/, "").replace(/\\/g, "/")
  const marker = "/node_modules/"
  const at = path.lastIndexOf(marker)
  if (at < 0) return null
  const parts = path.slice(at + marker.length).split("/")
  const name = parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0]
  return { name, root: path.slice(0, at + marker.length) + name }
}

function describe(root) {
  const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"))
  const file = readdirSync(root).find((entry) => LICENSE_FILE.test(entry))
  const repository =
    typeof manifest.repository === "string"
      ? manifest.repository
      : manifest.repository?.url
  return {
    name: manifest.name,
    version: manifest.version,
    license:
      typeof manifest.license === "string" ? manifest.license : "see below",
    homepage: manifest.homepage || repository || "",
    text: file ? readFileSync(join(root, file), "utf8").trim() : "",
  }
}

export function licenseNotices({
  output = "THIRD_PARTY_NOTICES.txt",
  root = process.cwd(),
} = {}) {
  const roots = new Map()
  return {
    name: "license-notices",
    apply: "build",
    renderChunk(_code, chunk) {
      for (const [id, info] of Object.entries(chunk.modules ?? {})) {
        if (!info || info.renderedLength <= 0) continue
        const found = packageOf(id)
        if (found && !roots.has(found.name)) roots.set(found.name, found.root)
      }
      return null
    },
    generateBundle() {
      if (!roots.size)
        this.error(
          "no bundled modules were seen; the license notices would be empty"
        )
      for (const name of ALWAYS) {
        const path = join(root, "node_modules", name)
        if (existsSync(join(path, "package.json"))) roots.set(name, path)
      }

      const entries = [...roots.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([, path]) => describe(path))

      const lines = [
        "DNS Load Forge dashboard - third-party notices",
        "",
        "The dashboard page (src/dnsloadforge/dashboard/index.html) is built from web/",
        "and bundles the packages below. The components in web/src/components/ui are",
        "derived from shadcn/ui (MIT). Each package's license follows its entry.",
        "",
      ]
      for (const entry of entries) {
        lines.push("=".repeat(78))
        lines.push(`${entry.name} ${entry.version}`)
        lines.push(`License: ${entry.license}`)
        if (entry.homepage)
          lines.push(`Source: ${entry.homepage.replace(/^git\+/, "")}`)
        lines.push("")
        lines.push(entry.text || "(no license file shipped with the package)")
        lines.push("")
      }
      this.emitFile({
        type: "asset",
        fileName: output,
        source: toAscii(lines.join("\n")),
      })
    },
  }
}
